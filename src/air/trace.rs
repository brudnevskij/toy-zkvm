use core::fmt;

use ark_ff::Field;

#[derive(Debug, Clone)]
pub struct TraceTable<F: Field> {
    n: usize,
    pub columns: Vec<Vec<F>>,
    names: Vec<String>,
}

impl<F: Field> TraceTable<F> {
    pub fn new(columns: Vec<Vec<F>>, names: Vec<String>) -> Self {
        assert!(!columns.is_empty(), "columns must have at least one column");
        let n = columns[0].len();
        assert!(n > 0, "number of columns must be greater than zero");
        assert!(
            names.is_empty() || names.len() == columns.len(),
            "names mismatch"
        );
        for (i, column) in columns.iter().enumerate() {
            let name = if !names.is_empty() {
                &names[i]
            } else {
                &format!("c_{}", i)
            };
            assert_eq!(
                column.len(),
                n,
                "column {i} length mismatch n = {n}, {}.len() = {}",
                name,
                column.len()
            );
        }
        Self { n, columns, names }
    }

    pub fn n(&self) -> usize {
        self.n
    }
    pub fn num_cols(&self) -> usize {
        self.columns.len()
    }
}

impl<F: Field + fmt::Debug> fmt::Display for TraceTable<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const COL_W: usize = 30; // width for each cell (incl truncated)
        const IDX_W: usize = 6; // width for row index column

        fn trunc_to(s: &str, max: usize) -> String {
            let len = s.chars().count();
            if len <= max {
                return s.to_string();
            }
            if max <= 1 {
                return "…".to_string();
            }
            let mut out: String = s.chars().take(max - 1).collect();
            out.push('…');
            out
        }

        fn pad_right_aligned(s: String, width: usize) -> String {
            // right-align inside fixed width
            let len = s.chars().count();
            if len >= width {
                s
            } else {
                let mut out = String::with_capacity(width);
                out.extend(std::iter::repeat(' ').take(width - len));
                out.push_str(&s);
                out
            }
        }

        // --- header ---
        write!(f, "{:>IDX_W$} ", "#", IDX_W = IDX_W)?;
        for i in 0..self.columns.len() {
            let name = if self.names.is_empty() {
                format!("c{i}")
            } else {
                self.names[i].clone()
            };
            let name = trunc_to(&name, COL_W);
            let name = pad_right_aligned(name, COL_W);
            write!(f, "| {} ", name)?;
        }
        writeln!(f)?;

        // --- rows ---
        for r in 0..self.n {
            write!(f, "{:>IDX_W$} ", r, IDX_W = IDX_W)?;
            for c in 0..self.columns.len() {
                let cell = format!("{:?}", self.columns[c][r]);
                let cell = trunc_to(&cell, COL_W);
                let cell = pad_right_aligned(cell, COL_W);
                write!(f, "| {} ", cell)?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}
