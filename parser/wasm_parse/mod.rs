use super::Parse;
use std::collections::HashMap;
use twiggy_ir::{self as ir, Id};
use twiggy_traits as traits;
use wasmparser::SectionWithLimitedItems;
use wasmparser::{self, Operator, SectionReader, Type};

#[derive(Default)]
pub struct SectionIndices {
    type_: Option<usize>,
    code: Option<usize>,
    functions: Vec<Id>,
    tables: Vec<Id>,
    memories: Vec<Id>,
    globals: Vec<Id>,
}

struct IndexedSection<'a>(usize, wasmparser::Payload<'a>);

impl<'a> Parse<'a> for wasmparser::BinaryReader<'a> {
    type ItemsExtra = ();

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        _extra: (),
    ) -> Result<(), traits::Error> {
        let initial_offset = self.current_position();
        let mut sections: Vec<IndexedSection<'_>> = Vec::new();
        let mut code_section: Option<IndexedSection<'_>> = None;
        let mut function_section: Option<IndexedSection<'_>> = None;
        let mut sizes: HashMap<usize, u32> = HashMap::new();

        // The function and code sections must be handled differently, so these
        // are not placed in the same `sections` array as the rest.
        let mut idx = 0;
        let mut buf = self.read_bytes(0)?;
        let mut parser = wasmparser::Parser::new(0);
        let mut total_readbytes = 0;
        let mut original_pos = self.clone();

        while !self.eof() {
            let (payload, mut size) = match parser.parse(&buf, self.eof())? {
                wasmparser::Chunk::NeedMoreData(hint) => {
                    total_readbytes += hint;
                    self.read_bytes(hint as usize)?;
                    buf = original_pos.clone().read_bytes(total_readbytes as usize)?;
                    continue;
                }
                wasmparser::Chunk::Parsed { consumed, payload } => (payload, consumed),
            };

            let indexed_section = IndexedSection(idx, payload);
            match indexed_section.1 {
                wasmparser::Payload::CodeSectionStart {
                    range,
                    size: code_size,
                    ..
                } => {
                    let section_header_start = original_pos.current_position();
                    original_pos.read_var_u32()?;
                    original_pos.read_var_u32()?;
                    let section_header_size =
                        original_pos.current_position() - section_header_start;

                    code_section = Some(IndexedSection(
                        idx,
                        wasmparser::Payload::UnknownSection {
                            id: 10,
                            contents: original_pos
                                .read_bytes(code_size as usize + size - section_header_size)?,
                            range,
                        },
                    ));
                    size = code_size as usize;
                    self.skip_bytes(code_size as usize)?;
                    parser.skip_section();
                }
                wasmparser::Payload::FunctionSection(_) => function_section = Some(indexed_section),
                _ => sections.push(indexed_section),
            };
            sizes.insert(idx, size as u32);
            idx += 1;

            original_pos = self.clone();
            total_readbytes = 0;
            buf = self.read_bytes(0)?;
        }

        let sections_cnt = sections.len()
            + if code_section.is_some() { 1 } else { 0 }
            + if function_section.is_some() { 1 } else { 0 };
        let id = Id::section(sections_cnt);
        items.add_root(ir::Item::new(
            id,
            "wasm magic bytes".to_string(),
            initial_offset as u32,
            ir::Misc::new(),
        ));

        // Before we actually parse any items prepare to parse a few sections
        // below, namely the code section. When parsing the code section we want
        // to try to assign human-readable names so we need the name section, if
        // present. Additionally we need to look at the number of imported
        // functions to handle the wasm function index space correctly.
        let names = parse_names_section(&sections)?;
        let imported_functions = count_imported_functions(&sections)?;

        // Next, we parse the function and code sections together, so that we
        // can collapse corresponding entries from the code and function
        // sections into a single representative IR item.
        match (function_section, code_section) {
            (Some(function_section), Some(code_section)) => (function_section, code_section)
                .parse_items(items, (imported_functions, &names, &sizes))?,
            _ => Err(traits::Error::with_msg(
                "function or code section is missing",
            ))?,
        };

        for IndexedSection(idx, section) in sections.into_iter() {
            let start = items.size_added();
            let name = get_section_name(&section);
            match section {
                wasmparser::Payload::CustomSection(reader) => {
                    CustomSectionReader(reader.name(), reader).parse_items(items, idx)?;
                }
                wasmparser::Payload::TypeSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::ImportSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::TableSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::MemorySection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::GlobalSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::ExportSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::StartSection { .. } => {
                    StartSection(section).parse_items(items, idx)?;
                }
                wasmparser::Payload::ElementSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::DataSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::DataCountSection { .. } => {
                    DataCountSection(section).parse_items(items, idx)?;
                }
                wasmparser::Payload::CodeSectionStart { .. }
                | wasmparser::Payload::FunctionSection(_) => {
                    unreachable!("unexpected code or function section found");
                }
                _ => {}
            };
            let id = Id::section(idx);
            let added = items.size_added() - start;
            let size = sizes
                .get(&idx)
                .ok_or_else(|| traits::Error::with_msg("Could not find section size"))?;
            assert!(added <= *size);
            items.add_root(ir::Item::new(id, name, size - added, ir::Misc::new()));
        }

        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        _extra: (),
    ) -> Result<(), traits::Error> {
        let mut sections: Vec<IndexedSection<'_>> = Vec::new();
        let mut code_section: Option<IndexedSection<'a>> = None;
        let mut function_section: Option<IndexedSection<'a>> = None;

        let mut idx = 0;
        let mut buf = self.read_bytes(0)?;
        let mut parser = wasmparser::Parser::new(0);
        let mut total_readbytes = 0;
        let mut original_pos = self.clone();

        while !self.eof() {
            let (payload, size) = match parser.parse(&buf, self.eof())? {
                wasmparser::Chunk::NeedMoreData(hint) => {
                    total_readbytes += hint;
                    self.read_bytes(hint as usize)?;
                    buf = original_pos.clone().read_bytes(total_readbytes as usize)?;
                    continue;
                }
                wasmparser::Chunk::Parsed { consumed, payload } => (payload, consumed),
            };

            let indexed_section = IndexedSection(idx, payload);
            match indexed_section.1 {
                wasmparser::Payload::CodeSectionStart {
                    range,
                    size: code_size,
                    ..
                } => {
                    let section_header_start = original_pos.current_position();
                    original_pos.read_var_u32()?;
                    original_pos.read_var_u32()?;
                    let section_header_size =
                        original_pos.current_position() - section_header_start;

                    code_section = Some(IndexedSection(
                        idx,
                        wasmparser::Payload::UnknownSection {
                            id: 10,
                            contents: original_pos
                                .read_bytes(code_size as usize + size - section_header_size)?,
                            range,
                        },
                    ));
                    self.skip_bytes(code_size as usize)?;
                    parser.skip_section();
                }
                wasmparser::Payload::FunctionSection(_) => function_section = Some(indexed_section),
                _ => sections.push(indexed_section),
            };
            idx += 1;
            original_pos = self.clone();
            total_readbytes = 0;
            buf = self.read_bytes(0)?;
        }

        // Like above we do some preprocessing here before actually drawing all
        // the edges below. Here we primarily want to learn some properties of
        // the wasm module, such as what `Id` is mapped to all index spaces in
        // the wasm module. To handle that we build up all this data in
        // `SectionIndices` here as we parse all the various sections.
        let mut indices = SectionIndices::default();
        for IndexedSection(idx, section) in sections.iter() {
            match section {
                wasmparser::Payload::TypeSection(_) => {
                    indices.type_ = Some(*idx);
                }
                wasmparser::Payload::ImportSection(reader) => {
                    for (i, import) in reader.to_owned().into_iter().enumerate() {
                        let id = Id::entry(*idx, i);
                        match import?.ty {
                            wasmparser::TypeRef::Func(_) => {
                                indices.functions.push(id);
                            }
                            wasmparser::TypeRef::Table(_) => {
                                indices.tables.push(id);
                            }
                            wasmparser::TypeRef::Memory(_) => {
                                indices.memories.push(id);
                            }
                            wasmparser::TypeRef::Global(_) => {
                                indices.globals.push(id);
                            }
                            _ => {}
                        }
                    }
                }
                wasmparser::Payload::GlobalSection(reader) => {
                    for i in 0..reader.get_count() {
                        let id = Id::entry(*idx, i as usize);
                        indices.globals.push(id);
                    }
                }
                wasmparser::Payload::MemorySection(reader) => {
                    for i in 0..reader.get_count() {
                        let id = Id::entry(*idx, i as usize);
                        indices.memories.push(id);
                    }
                }
                wasmparser::Payload::TableSection(reader) => {
                    for i in 0..reader.get_count() {
                        let id = Id::entry(*idx, i as usize);
                        indices.tables.push(id);
                    }
                }
                wasmparser::Payload::CodeSectionStart { .. } => {
                    Err(traits::Error::with_msg("unexpected code section"))?
                }
                wasmparser::Payload::FunctionSection(_) => {
                    Err(traits::Error::with_msg("unexpected function section"))?
                }
                _ => {}
            }
        }
        if let (Some(IndexedSection(_, function_section)), Some(IndexedSection(code_idx, _))) =
            (function_section.as_ref(), code_section.as_ref())
        {
            indices.code = Some(*code_idx);

            if let wasmparser::Payload::FunctionSection(reader) = function_section {
                for i in 0..reader.get_count() {
                    let id = Id::entry(*code_idx, i as usize);
                    indices.functions.push(id);
                }
            }
        }

        match (function_section, code_section) {
            (Some(function_section), Some(code_section)) => {
                (function_section, code_section).parse_edges(items, &indices)?
            }
            _ => panic!("function or code section is missing"),
        };
        for IndexedSection(idx, section) in sections.into_iter() {
            match section {
                wasmparser::Payload::CustomSection(reader) => {
                    CustomSectionReader(reader.name(), reader).parse_edges(items, ())?;
                }
                wasmparser::Payload::TypeSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::ImportSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::TableSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::MemorySection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::GlobalSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::ExportSection(mut reader) => {
                    reader.parse_edges(items, (&indices, idx))?;
                }
                wasmparser::Payload::StartSection { .. } => {
                    StartSection(section).parse_edges(items, (&indices, idx))?;
                }
                wasmparser::Payload::ElementSection(mut reader) => {
                    reader.parse_edges(items, (&indices, idx))?;
                }
                wasmparser::Payload::DataSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::DataCountSection { .. } => {
                    DataCountSection(section).parse_edges(items, ())?;
                }
                wasmparser::Payload::CodeSectionEntry(_)
                | wasmparser::Payload::FunctionSection(_) => {
                    unreachable!("unexpected code or function section found");
                }
                _ => {}
            }
        }

        Ok(())
    }
}

fn get_section_name(section: &wasmparser::Payload<'_>) -> String {
    match payload2code(section) {
        wasmparser::SectionCode::Custom { name, .. } => {
            format!("custom section '{}' headers", name)
        }
        wasmparser::SectionCode::Type => "type section headers".to_string(),
        wasmparser::SectionCode::Import => "import section headers".to_string(),
        wasmparser::SectionCode::Function => "function section headers".to_string(),
        wasmparser::SectionCode::Table => "table section headers".to_string(),
        wasmparser::SectionCode::Memory => "memory section headers".to_string(),
        wasmparser::SectionCode::Global => "global section headers".to_string(),
        wasmparser::SectionCode::Export => "export section headers".to_string(),
        wasmparser::SectionCode::Start => "start section headers".to_string(),
        wasmparser::SectionCode::Element => "element section headers".to_string(),
        wasmparser::SectionCode::Code => "code section headers".to_string(),
        wasmparser::SectionCode::Data => "data section headers".to_string(),
        wasmparser::SectionCode::DataCount => "data count section headers".to_string(),
        _ => "unknown section headers".to_string(),
    }
}

fn parse_names_section<'a>(
    indexed_sections: &[IndexedSection<'a>],
) -> Result<HashMap<usize, &'a str>, traits::Error> {
    let mut names = HashMap::new();
    for IndexedSection(_, section) in indexed_sections.iter() {
        if let (
            wasmparser::Payload::CustomSection(reader),
            wasmparser::SectionCode::Custom { name: "name", .. },
        ) = (section, payload2code(section))
        {
            for subsection in wasmparser::NameSectionReader::new(reader.data(), 0)? {
                // We use a rather old version of wasmparser. This is a workaround
                // to skip new types of name subsections instead of aborting.
                let subsection = if let Ok(subsection) = subsection {
                    subsection
                } else {
                    continue;
                };
                let f = match subsection {
                    wasmparser::Name::Function(f) => f,
                    _ => continue,
                };
                let mut map = f.get_map()?;
                for _ in 0..map.get_count() {
                    let naming = map.read()?;
                    names.insert(naming.index as usize, naming.name);
                }
            }
        }
    }
    Ok(names)
}

fn count_imported_functions<'a>(
    indexed_sections: &[IndexedSection<'a>],
) -> Result<usize, traits::Error> {
    let mut imported_functions = 0;
    for IndexedSection(_, section) in indexed_sections.iter() {
        if let wasmparser::Payload::ImportSection(ref reader) = section {
            for import in reader.to_owned().into_iter() {
                if let wasmparser::TypeRef::Func(_) = import?.ty {
                    imported_functions += 1;
                }
            }
        }
    }
    Ok(imported_functions)
}

impl<'a> Parse<'a> for (IndexedSection<'a>, IndexedSection<'a>) {
    type ItemsExtra = (usize, &'a HashMap<usize, &'a str>, &'a HashMap<usize, u32>);

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (imported_functions, names, sizes): Self::ItemsExtra,
    ) -> Result<(), traits::Error> {
        let (
            IndexedSection(func_section_idx, func_section),
            IndexedSection(code_section_idx, code_section),
        ) = self;

        let func_reader = if let wasmparser::Payload::FunctionSection(reader) = func_section {
            reader
        } else {
            return Ok(());
        };
        let mut code_reader =
            if let wasmparser::Payload::UnknownSection { contents, .. } = code_section {
                wasmparser::CodeSectionReader::new(contents, 0)?
            } else {
                return Ok(());
            };

        let func_items: Vec<ir::Item> = iterate_with_size(func_reader)
            .enumerate()
            .map(|(i, func)| {
                let (_func, size) = func?;
                let id = Id::entry(*func_section_idx, i);
                let name = format!("func[{}]", i);
                let item = ir::Item::new(id, name, size, ir::Misc::new());
                Ok(item)
            })
            .collect::<Result<_, traits::Error>>()?;

        let code_items: Vec<ir::Item> = iterate_with_size(&mut code_reader)
            .zip(func_items.into_iter())
            .enumerate()
            .map(|(i, (body, func))| {
                let (_body, size) = body?;
                let id = Id::entry(*code_section_idx, i);
                let name = names
                    .get(&(i + imported_functions))
                    .map_or_else(|| format!("code[{}]", i), |name| name.to_string());
                let code = ir::Code::new(&name);
                let item = ir::Item::new(id, name, size + func.size(), code);
                Ok(item)
            })
            .collect::<Result<_, traits::Error>>()?;

        let start = items.size_added();
        let name = get_section_name(code_section);
        for item in code_items.into_iter() {
            items.add_item(item);
        }
        let id = Id::section(*code_section_idx);
        let added = items.size_added() - start;
        let size = sizes
            .get(&code_section_idx)
            .ok_or_else(|| traits::Error::with_msg("Could not find section size"))?
            + sizes
                .get(&func_section_idx)
                .ok_or_else(|| traits::Error::with_msg("Could not find section size"))?;
        assert!(added <= size);
        items.add_root(ir::Item::new(id, name, size - added, ir::Misc::new()));

        Ok(())
    }

    type EdgesExtra = &'a SectionIndices;

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        indices: Self::EdgesExtra,
    ) -> Result<(), traits::Error> {
        let (IndexedSection(_, function_section), IndexedSection(code_section_idx, code_section)) =
            self;

        let func_reader = if let wasmparser::Payload::FunctionSection(reader) = function_section {
            reader
        } else {
            return Ok(());
        };
        let mut code_reader =
            if let wasmparser::Payload::UnknownSection { contents, .. } = code_section {
                wasmparser::CodeSectionReader::new(contents, 0)?
            } else {
                return Ok(());
            };

        type Edge = (ir::Id, ir::Id);

        let mut edges: Vec<Edge> = Vec::new();

        // Function section reader parsing.
        for (func_i, type_ref) in iterate_with_size(func_reader).enumerate() {
            let (type_ref, _) = type_ref?;
            if let Some(type_idx) = indices.type_ {
                let type_id = Id::entry(type_idx, type_ref as usize);
                if let Some(code_idx) = indices.code {
                    let body_id = Id::entry(code_idx, func_i);
                    edges.push((body_id, type_id));
                }
            }
        }

        // Code section reader parsing.
        for (b_i, body) in iterate_with_size(&mut code_reader).enumerate() {
            let (body, _size) = body?;
            let body_id = Id::entry(*code_section_idx, b_i);

            let mut cache = None;
            for op in body.get_operators_reader()? {
                let prev = cache.take();
                match op? {
                    Operator::Call { function_index } => {
                        let f_id = indices.functions[function_index as usize];
                        edges.push((body_id, f_id));
                    }

                    // TODO: Rather than looking at indirect calls, need to look
                    // at where the vtables get initialized and/or vtable
                    // indices get pushed onto the stack.
                    Operator::CallIndirect { .. } => continue,

                    Operator::GlobalGet { global_index } | Operator::GlobalSet { global_index } => {
                        let g_id = indices.globals[global_index as usize];
                        edges.push((body_id, g_id));
                    }

                    Operator::I32Load { memarg }
                    | Operator::I32Load8S { memarg }
                    | Operator::I32Load8U { memarg }
                    | Operator::I32Load16S { memarg }
                    | Operator::I32Load16U { memarg }
                    | Operator::I64Load { memarg }
                    | Operator::I64Load8S { memarg }
                    | Operator::I64Load8U { memarg }
                    | Operator::I64Load16S { memarg }
                    | Operator::I64Load16U { memarg }
                    | Operator::I64Load32S { memarg }
                    | Operator::I64Load32U { memarg }
                    | Operator::F32Load { memarg }
                    | Operator::F64Load { memarg } => {
                        if let Some(Operator::I32Const { value }) = prev {
                            if let Some(data_id) =
                                items.get_data(value as u32 + memarg.offset as u32)
                            {
                                edges.push((body_id, data_id));
                            }
                        }
                    }
                    other => cache = Some(other),
                }
            }
        }

        edges
            .into_iter()
            .for_each(|(from, to)| items.add_edge(from, to));

        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::NameSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        let mut i = 0;
        while !self.eof() {
            let start = self.original_position();
            // We use a rather old version of wasmparser. This is a workaround
            // to skip new types of name subsections instead of aborting.
            let subsection = if let Ok(subsection) = self.read() {
                subsection
            } else {
                continue;
            };
            let size = (self.original_position() - start) as u32;
            let name = match subsection {
                wasmparser::Name::Module(_) => "\"module name\" subsection",
                wasmparser::Name::Function(_) => "\"function names\" subsection",
                wasmparser::Name::Local(_) => "\"local names\" subsection",
                _ => "unknown subsection",
            };
            let id = Id::entry(idx, i);
            items.add_root(ir::Item::new(id, name, size, ir::DebugInfo::new()));
            i += 1;
        }

        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

struct CustomSectionReader<'a>(&'a str, wasmparser::CustomSectionReader<'a>);

impl<'a> Parse<'a> for CustomSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        let name = self.0;
        if name == "name" {
            wasmparser::NameSectionReader::new(self.1.data(), 0)?.parse_items(items, idx)?;
        } else {
            let range = self.1.range();
            let size = (range.end - range.start) as u32;
            let id = Id::entry(idx, 0);
            let name = format!("custom section '{}'", self.0);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::TypeSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, ty) in iterate_with_size(self).enumerate() {
            let (ty, size) = ty?;
            let id = Id::entry(idx, i);

            let mut name = format!("type[{}]: (", i);
            let wasmparser::TypeDef::Func(ty) = ty;

            for (i, param) in ty.params.iter().enumerate() {
                if i != 0 {
                    name.push_str(", ");
                }
                name.push_str(ty2str(*param));
            }
            name.push_str(") -> ");

            match ty.returns.len() {
                0 => name.push_str("nil"),
                1 => name.push_str(ty2str(ty.returns[0])),
                _ => {
                    name.push_str("(");
                    for (i, result) in ty.returns.iter().enumerate() {
                        if i != 0 {
                            name.push_str(", ");
                        }
                        name.push_str(ty2str(*result));
                    }
                    name.push_str(")");
                }
            }

            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::ImportSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, imp) in iterate_with_size(self).enumerate() {
            let (imp, size) = imp?;
            let id = Id::entry(idx, i);
            let name = format!("import {}::{}", imp.module, imp.name);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, (): ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::TableSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, entry) in iterate_with_size(self).enumerate() {
            let (_entry, size) = entry?;
            let id = Id::entry(idx, i);
            let name = format!("table[{}]", i);
            items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::MemorySectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, mem) in iterate_with_size(self).enumerate() {
            let (_mem, size) = mem?;
            let id = Id::entry(idx, i);
            let name = format!("memory[{}]", i);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::GlobalSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, g) in iterate_with_size(self).enumerate() {
            let (g, size) = g?;
            let id = Id::entry(idx, i);
            let name = format!("global[{}]", i);
            let ty = ty2str(g.ty.content_type).to_string();
            items.add_item(ir::Item::new(id, name, size, ir::Data::new(Some(ty))));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::ExportSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, exp) in iterate_with_size(self).enumerate() {
            let (exp, size) = exp?;
            let id = Id::entry(idx, i);
            let name = format!("export \"{}\"", exp.name);
            items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = (&'a SectionIndices, usize);

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (indices, idx): Self::EdgesExtra,
    ) -> Result<(), traits::Error> {
        for (i, exp) in iterate_with_size(self).enumerate() {
            let (exp, _) = exp?;
            let exp_id = Id::entry(idx, i);
            match exp.kind {
                wasmparser::ExternalKind::Func => {
                    items.add_edge(exp_id, indices.functions[exp.index as usize]);
                }
                wasmparser::ExternalKind::Table => {
                    items.add_edge(exp_id, indices.tables[exp.index as usize]);
                }
                wasmparser::ExternalKind::Memory => {
                    items.add_edge(exp_id, indices.memories[exp.index as usize]);
                }
                wasmparser::ExternalKind::Global => {
                    items.add_edge(exp_id, indices.globals[exp.index as usize]);
                }
                _ => {}
            }
        }

        Ok(())
    }
}

struct StartSection<'a>(wasmparser::Payload<'a>);

impl<'a> Parse<'a> for StartSection<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        if let wasmparser::Payload::StartSection { ref range, .. } = self.0 {
            let size = (range.end - range.start) as u32;
            let id = Id::section(idx);
            let name = "\"start\" section";
            items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        }

        Ok(())
    }

    type EdgesExtra = (&'a SectionIndices, usize);

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (indices, idx): Self::EdgesExtra,
    ) -> Result<(), traits::Error> {
        if let wasmparser::Payload::StartSection { func, .. } = self.0 {
            items.add_edge(Id::section(idx), indices.functions[func as usize]);
        }

        Ok(())
    }
}

struct DataCountSection<'a>(wasmparser::Payload<'a>);

impl<'a> Parse<'a> for DataCountSection<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        if let wasmparser::Payload::StartSection { ref range, .. } = self.0 {
            let size = (range.end - range.start) as u32;
            let id = Id::section(idx);
            let name = "\"data count\" section";
            items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        }

        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _items: &mut ir::ItemsBuilder, (): ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::ElementSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, elem) in iterate_with_size(self).enumerate() {
            let (_elem, size) = elem?;
            let id = Id::entry(idx, i);
            let name = format!("elem[{}]", i);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = (&'a SectionIndices, usize);

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (indices, idx): Self::EdgesExtra,
    ) -> Result<(), traits::Error> {
        for (i, elem) in iterate_with_size(self).enumerate() {
            let (elem, _size) = elem?;
            let elem_id = Id::entry(idx, i);

            match elem.kind {
                wasmparser::ElementKind::Active { table_index, .. } => {
                    items.add_edge(indices.tables[table_index as usize], elem_id);
                }
                _ => {}
            }
            for func_idx in elem.items.get_items_reader()? {
                if let wasmparser::ElementItem::Func(func_idx) = func_idx? {
                    items.add_edge(elem_id, indices.functions[func_idx as usize]);
                }
            }
        }

        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::DataSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        idx: usize,
    ) -> Result<(), traits::Error> {
        for (i, d) in iterate_with_size(self).enumerate() {
            let (d, size) = d?;
            let id = Id::entry(idx, i);
            let name = format!("data[{}]", i);
            items.add_item(ir::Item::new(id, name, size, ir::Data::new(None)));

            // Get the constant address (if any) from the initialization
            // expression.
            if let wasmparser::DataKind::Active { init_expr, .. } = d.kind {
                let mut iter = init_expr.get_operators_reader();
                let offset = match iter.read()? {
                    Operator::I32Const { value } => Some(i64::from(value)),
                    Operator::I64Const { value } => Some(value),
                    _ => None,
                };

                if let Some(off) = offset {
                    let length = d.data.len(); // size of data
                    items.link_data(off, length, id);
                }
            }
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> Result<(), traits::Error> {
        Ok(())
    }
}

fn iterate_with_size<'a, S: SectionWithLimitedItems + SectionReader>(
    s: &'a mut S,
) -> impl Iterator<Item = Result<(S::Item, u32), traits::Error>> + 'a {
    let count = s.get_count();
    (0..count).map(move |i| {
        let start = s.original_position();
        let item = s.read()?;
        let size = (s.original_position() - start) as u32;
        if i == count - 1 {
            s.ensure_end()?;
        }
        Ok((item, size))
    })
}

fn ty2str(t: Type) -> &'static str {
    match t {
        Type::I32 => "i32",
        Type::I64 => "i64",
        Type::F32 => "f32",
        Type::F64 => "f64",
        Type::V128 => "v128",
        Type::FuncRef => "funcref",
        Type::ExternRef => "externref",
    }
}

fn payload2code<'a>(payload: &wasmparser::Payload<'a>) -> wasmparser::SectionCode<'a> {
    match payload {
        wasmparser::Payload::CustomSection(d) => wasmparser::SectionCode::Custom {
            name: d.name(),
            kind: wasmparser::CustomSectionKind::Unknown,
        },
        wasmparser::Payload::TypeSection(_) => wasmparser::SectionCode::Type,
        wasmparser::Payload::ImportSection(_) => wasmparser::SectionCode::Import,
        wasmparser::Payload::FunctionSection(_) => wasmparser::SectionCode::Function,
        wasmparser::Payload::TableSection(_) => wasmparser::SectionCode::Table,
        wasmparser::Payload::MemorySection(_) => wasmparser::SectionCode::Memory,
        wasmparser::Payload::GlobalSection(_) => wasmparser::SectionCode::Global,
        wasmparser::Payload::ExportSection(_) => wasmparser::SectionCode::Export,
        wasmparser::Payload::StartSection { .. } => wasmparser::SectionCode::Start,
        wasmparser::Payload::ElementSection(_) => wasmparser::SectionCode::Element,
        wasmparser::Payload::CodeSectionStart { .. } => wasmparser::SectionCode::Code,
        wasmparser::Payload::DataSection(_) => wasmparser::SectionCode::Data,
        wasmparser::Payload::DataCountSection { .. } => wasmparser::SectionCode::DataCount,
        wasmparser::Payload::TagSection(_) => wasmparser::SectionCode::Tag,
        _ => wasmparser::SectionCode::Custom {
            name: "unknown",
            kind: wasmparser::CustomSectionKind::Unknown,
        },
    }
}
