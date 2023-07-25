/**
 * @name nghttp2-b611c43a5de061ec21b343967e1b64c45c373d7e-gen_hash
 * @id cpp/nghttp2/b611c43a5de061ec21b343967e1b64c45c373d7e/gen-hash
 * @description nghttp2-b611c43a5de061ec21b343967e1b64c45c373d7e-mrbgems/mruby-compiler/core/codegen.c-gen_hash CVE-2022-0326
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vval_1597, BlockStmt target_3, LogicalAndExpr target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vval_1597
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_3
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlen_1601, BlockStmt target_3, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vlen_1601
		and target_1.getLesserOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_3
}

predicate func_2(Variable vupdate_1602, Function func, IfStmt target_2) {
		target_2.getCondition().(VariableAccess).getTarget()=vupdate_1602
		and target_2.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vlen_1601, BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pop_n_")
		and target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_1601
		and target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("genop_2")
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="sp"
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlen_1601
}

predicate func_4(Parameter vval_1597, LogicalAndExpr target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vval_1597
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="sp"
}

from Function func, Parameter vval_1597, Variable vlen_1601, Variable vupdate_1602, RelationalOperation target_1, IfStmt target_2, BlockStmt target_3, LogicalAndExpr target_4
where
not func_0(vval_1597, target_3, target_4)
and func_1(vlen_1601, target_3, target_1)
and func_2(vupdate_1602, func, target_2)
and func_3(vlen_1601, target_3)
and func_4(vval_1597, target_4)
and vval_1597.getType().hasName("int")
and vlen_1601.getType().hasName("int")
and vupdate_1602.getType().hasName("mrb_bool")
and vval_1597.getParentScope+() = func
and vlen_1601.getParentScope+() = func
and vupdate_1602.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
