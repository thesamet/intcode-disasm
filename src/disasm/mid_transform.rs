use super::{
    low_ir::FatInstruction,
    mid_flow::LoopId,
    mid_ir::{Expr, FunctionRange, MidIR},
};

pub trait MidVisitor {
    fn visit_statement(&mut self, mid: &MidIR) {
        match mid {
            MidIR::Block(b) => self.visit_block(b),
            MidIR::If(e, then, els) => self.visit_if_else(e, then, els),
            MidIR::Loop(l, block) => self.visit_loop(l, block),
            MidIR::Break(l) => self.visit_break(l),
            MidIR::Continue(l) => self.visit_continue(l),
            MidIR::Unknown(_, _) => {}
            MidIR::Return() => self.visit_return(),
            MidIR::Assign(lhs, rhs) => self.visit_assign(lhs, rhs),
            MidIR::Output(expr) => self.visit_output(expr),
            MidIR::While(l, header, cond, body) => self.visit_while(l, header, cond, body),
            MidIR::DoWhile(l, body, cond) => self.visit_do_while(l, body, cond),
            MidIR::Halt() => self.visit_halt(),
        }
    }

    fn visit_block(&mut self, b: &Vec<MidIR>) {
        for i in b {
            self.visit_statement(i);
        }
    }

    fn visit_if_else(&mut self, e: &Expr, then: &MidIR, els: &Option<Box<MidIR>>) {
        self.visit_expr(e);
        self.visit_statement(then);
        if let Some(els) = els {
            self.visit_statement(els);
        }
    }

    fn visit_loop(&mut self, _: &LoopId, body: &MidIR) {
        self.visit_statement(body);
    }

    fn visit_break(&mut self, _: &LoopId) {}

    fn visit_continue(&mut self, _: &LoopId) {}

    fn visit_return(&mut self) {}

    fn visit_assign(&mut self, lhs: &Expr, rhs: &Expr) {
        self.visit_expr(lhs);
        self.visit_expr(rhs);
    }

    fn visit_output(&mut self, expr: &Expr) {
        self.visit_expr(expr);
    }

    fn visit_while(&mut self, _: &LoopId, header: &Option<Box<MidIR>>, cond: &Expr, body: &MidIR) {
        if let Some(header) = header {
            self.visit_statement(header);
        }
        self.visit_expr(cond);
        self.visit_statement(body);
    }

    fn visit_do_while(&mut self, _: &LoopId, body: &MidIR, cond: &Expr) {
        self.visit_statement(body);
        self.visit_expr(cond);
    }

    fn visit_halt(&mut self) {}

    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Input() => self.visit_input(),
            Expr::Var(v) => self.visit_var(v),
            Expr::InArg(v) => self.visit_inarg(v),
            Expr::OutArg(v) => self.visit_outarg(v),
            Expr::MemRef(expr) => self.visit_memref(expr),
            Expr::Literal(l) => self.visit_literal(l),
            Expr::Add(expr, expr1) => self.visit_add(expr, expr1),
            Expr::Mul(expr, expr1) => self.visit_mul(expr, expr1),
            Expr::NotEqual(expr, expr1) => self.visit_not_equal(expr, expr1),
            Expr::Equal(expr, expr1) => self.visit_equal(expr, expr1),
            Expr::LessThan(expr, expr1) => self.visit_less_than(expr, expr1),
            Expr::GreaterOrEqual(expr, expr1) => self.visit_greater_or_equal(expr, expr1),
            Expr::Negate(expr) => self.visit_negate(expr),
            Expr::If(expr, expr1, expr2) => self.visit_if_expr(expr, expr1, expr2),
            Expr::FunctionCall(expr, exprs) => self.visit_function_call(expr, exprs),
            Expr::Ignore => self.visit_ignore(),
        }
    }

    fn visit_function_call(&mut self, expr: &Expr, exprs: &Vec<Expr>) {
        self.visit_expr(expr);
        for e in exprs {
            self.visit_expr(e);
        }
    }

    fn visit_input(&mut self) {}

    fn visit_var(&mut self, _: &String) {}

    fn visit_inarg(&mut self, _: &usize) {}

    fn visit_outarg(&mut self, _: &usize) {}

    fn visit_memref(&mut self, expr: &Expr) {
        self.visit_expr(expr);
    }

    fn visit_literal(&mut self, _: &i128) {}

    fn visit_add(&mut self, lhs: &Expr, rhs: &Expr) {
        self.visit_expr(lhs);
        self.visit_expr(rhs);
    }

    fn visit_mul(&mut self, lhs: &Expr, rhs: &Expr) {
        self.visit_expr(lhs);
        self.visit_expr(rhs);
    }

    fn visit_not_equal(&mut self, lhs: &Expr, rhs: &Expr) {
        self.visit_expr(lhs);
        self.visit_expr(rhs);
    }

    fn visit_equal(&mut self, lhs: &Expr, rhs: &Expr) {
        self.visit_expr(lhs);
        self.visit_expr(rhs);
    }

    fn visit_less_than(&mut self, lhs: &Expr, rhs: &Expr) {
        self.visit_expr(lhs);
        self.visit_expr(rhs);
    }

    fn visit_greater_or_equal(&mut self, lhs: &Expr, rhs: &Expr) {
        self.visit_expr(lhs);
        self.visit_expr(rhs);
    }

    fn visit_negate(&mut self, expr: &Expr) {
        self.visit_expr(expr);
    }

    fn visit_if_expr(&mut self, cond: &Expr, then: &Expr, els: &Expr) {
        self.visit_expr(cond);
        self.visit_expr(then);
        self.visit_expr(els);
    }

    fn visit_ignore(&mut self) {}
}

pub trait MidTransformer {
    fn transform_statement(&mut self, mid: &MidIR) -> MidIR {
        match mid {
            MidIR::Block(b) => self.transform_block(b),
            MidIR::If(e, then, els) => self.transform_if_else(e, then, els),
            MidIR::Loop(l, block) => self.transform_loop(l, block),
            MidIR::Break(l) => self.transform_break(l),
            MidIR::Continue(l) => self.transform_continue(l),
            MidIR::Unknown(offset, inst) => self.transform_unknown(offset, inst),
            MidIR::Return() => self.transform_return(),
            MidIR::Assign(lhs, rhs) => self.transform_assign(lhs, rhs),
            MidIR::Output(expr) => self.transform_output(expr),
            MidIR::While(l, header, cond, body) => self.transform_while(l, header, cond, body),
            MidIR::DoWhile(l, body, cond) => self.transform_do_while(l, body, cond),
            MidIR::Halt() => self.transform_halt(),
        }
    }

    fn transform_block(&mut self, b: &[MidIR]) -> MidIR {
        MidIR::Block(b.iter().map(|i| self.transform_statement(i)).collect())
    }

    fn transform_if_else(&mut self, e: &Expr, then: &MidIR, els: &Option<Box<MidIR>>) -> MidIR {
        MidIR::If(
            self.transform_expr(e),
            Box::new(self.transform_statement(then)),
            els.as_ref()
                .map(|els| Box::new(self.transform_statement(els))),
        )
    }

    fn transform_loop(&mut self, l: &LoopId, body: &MidIR) -> MidIR {
        MidIR::Loop(*l, Box::new(self.transform_statement(body)))
    }

    fn transform_break(&mut self, l: &LoopId) -> MidIR {
        MidIR::Break(*l)
    }

    fn transform_continue(&mut self, l: &LoopId) -> MidIR {
        MidIR::Continue(*l)
    }

    fn transform_unknown(&mut self, offset: &usize, inst: &FatInstruction) -> MidIR {
        MidIR::Unknown(*offset, inst.clone())
    }

    fn transform_return(&mut self) -> MidIR {
        MidIR::Return()
    }

    fn transform_halt(&mut self) -> MidIR {
        MidIR::Halt()
    }

    fn transform_assign(&mut self, lhs: &Expr, rhs: &Expr) -> MidIR {
        MidIR::Assign(self.transform_expr(lhs), self.transform_expr(rhs))
    }

    fn transform_output(&mut self, expr: &Expr) -> MidIR {
        MidIR::Output(self.transform_expr(expr))
    }

    fn transform_while(
        &mut self,
        l: &LoopId,
        header: &Option<Box<MidIR>>,
        cond: &Expr,
        body: &MidIR,
    ) -> MidIR {
        MidIR::While(
            *l,
            header
                .as_ref()
                .map(|h| Box::new(self.transform_statement(h))),
            self.transform_expr(cond),
            Box::new(self.transform_statement(body)),
        )
    }

    fn transform_do_while(&mut self, l: &LoopId, body: &MidIR, cond: &Expr) -> MidIR {
        MidIR::DoWhile(
            *l,
            Box::new(self.transform_statement(body)),
            self.transform_expr(cond),
        )
    }

    fn transform_expr(&mut self, expr: &Expr) -> Expr {
        match expr {
            Expr::Input() => self.transform_input(),
            Expr::Var(v) => self.transform_var(v),
            Expr::InArg(v) => self.transform_inarg(v),
            Expr::OutArg(v) => self.transform_outarg(v),
            Expr::MemRef(expr) => self.transform_memref(expr),
            Expr::Literal(l) => self.transform_literal(l),
            Expr::Add(expr, expr1) => self.transform_add(expr, expr1),
            Expr::Mul(expr, expr1) => self.transform_mul(expr, expr1),
            Expr::NotEqual(expr, expr1) => self.transform_not_equal(expr, expr1),
            Expr::Equal(expr, expr1) => self.transform_equal(expr, expr1),
            Expr::LessThan(expr, expr1) => self.transform_less_than(expr, expr1),
            Expr::GreaterOrEqual(expr, expr1) => self.transform_greater_or_equal(expr, expr1),
            Expr::Negate(expr) => self.transform_negate(expr),
            Expr::If(expr, expr1, expr2) => self.transform_if_expr(expr, expr1, expr2),
            Expr::FunctionCall(expr, exprs) => self.transform_function_call(expr, exprs),
            Expr::Ignore => self.transform_ignore(),
        }
    }

    fn transform_function_call(&mut self, expr: &Expr, exprs: &[Expr]) -> Expr {
        Expr::FunctionCall(
            Box::new(self.transform_expr(expr)),
            exprs.iter().map(|e| self.transform_expr(e)).collect(),
        )
    }

    fn transform_input(&mut self) -> Expr {
        Expr::Input()
    }

    fn transform_var(&mut self, v: &str) -> Expr {
        Expr::Var(v.to_string())
    }

    fn transform_inarg(&mut self, v: &usize) -> Expr {
        Expr::InArg(*v)
    }

    fn transform_outarg(&mut self, v: &usize) -> Expr {
        Expr::OutArg(*v)
    }

    fn transform_memref(&mut self, expr: &Expr) -> Expr {
        Expr::MemRef(Box::new(self.transform_expr(expr)))
    }

    fn transform_literal(&mut self, l: &i128) -> Expr {
        Expr::Literal(*l)
    }

    fn transform_add(&mut self, lhs: &Expr, rhs: &Expr) -> Expr {
        Expr::Add(
            Box::new(self.transform_expr(lhs)),
            Box::new(self.transform_expr(rhs)),
        )
    }

    fn transform_mul(&mut self, lhs: &Expr, rhs: &Expr) -> Expr {
        Expr::Mul(
            Box::new(self.transform_expr(lhs)),
            Box::new(self.transform_expr(rhs)),
        )
    }

    fn transform_not_equal(&mut self, lhs: &Expr, rhs: &Expr) -> Expr {
        Expr::NotEqual(
            Box::new(self.transform_expr(lhs)),
            Box::new(self.transform_expr(rhs)),
        )
    }

    fn transform_equal(&mut self, lhs: &Expr, rhs: &Expr) -> Expr {
        Expr::Equal(
            Box::new(self.transform_expr(lhs)),
            Box::new(self.transform_expr(rhs)),
        )
    }

    fn transform_less_than(&mut self, lhs: &Expr, rhs: &Expr) -> Expr {
        Expr::LessThan(
            Box::new(self.transform_expr(lhs)),
            Box::new(self.transform_expr(rhs)),
        )
    }

    fn transform_greater_or_equal(&mut self, lhs: &Expr, rhs: &Expr) -> Expr {
        Expr::GreaterOrEqual(
            Box::new(self.transform_expr(lhs)),
            Box::new(self.transform_expr(rhs)),
        )
    }

    fn transform_negate(&mut self, expr: &Expr) -> Expr {
        Expr::Negate(Box::new(self.transform_expr(expr)))
    }

    fn transform_if_expr(&mut self, cond: &Expr, then: &Expr, els: &Expr) -> Expr {
        Expr::If(
            Box::new(self.transform_expr(cond)),
            Box::new(self.transform_expr(then)),
            Box::new(self.transform_expr(els)),
        )
    }

    fn transform_ignore(&mut self) -> Expr {
        Expr::Ignore
    }
}

// Utility function to apply a transformer to a MidIR
pub fn transform_ir<T: MidTransformer>(mid: &MidIR, transformer: &mut T) -> MidIR {
    transformer.transform_statement(mid)
}

struct RenameVarsOnStack {
    first_var: usize,
}

impl MidTransformer for RenameVarsOnStack {
    fn transform_inarg(&mut self, v: &usize) -> Expr {
        if *v >= self.first_var {
            Expr::Var(format!("s{}", v + 1 - self.first_var))
        } else {
            Expr::Var(format!("i{}", v))
        }
    }
}

pub fn rename_vars_on_stack(fr: &mut FunctionRange) {
    let mut transformer = RenameVarsOnStack {
        first_var: fr.args.len() + 1,
    };
    fr.block = transform_ir(&fr.block, &mut transformer);
}

struct FindFunctionCalls {
    calls: Vec<(Expr, Vec<Expr>)>,
}

impl FindFunctionCalls {
    fn new() -> Self {
        FindFunctionCalls { calls: vec![] }
    }
}

impl MidVisitor for FindFunctionCalls {
    fn visit_function_call(&mut self, expr: &Expr, args: &Vec<Expr>) {
        self.calls.push((expr.clone(), args.clone()));
        self.visit_expr(expr);
        for e in args {
            self.visit_expr(e);
        }
    }
}

pub fn find_static_function_calls(mid: &MidIR) -> Vec<(usize, Vec<Expr>)> {
    let mut visitor = FindFunctionCalls::new();
    visitor.visit_statement(mid);
    visitor
        .calls
        .iter()
        .filter_map(|(e, args)| e.literal().map(|l| (l as usize, args.clone())))
        .collect()
}

pub fn find_dynamic_function_calls(mid: &MidIR) -> Vec<(Expr, Vec<Expr>)> {
    let mut visitor = FindFunctionCalls::new();
    visitor.visit_statement(mid);
    visitor
        .calls
        .iter()
        .filter(|(e, _)| e.literal().is_none())
        .cloned()
        .collect()
}
