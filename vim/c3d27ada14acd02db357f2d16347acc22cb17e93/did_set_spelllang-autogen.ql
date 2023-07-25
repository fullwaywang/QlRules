/**
 * @name vim-c3d27ada14acd02db357f2d16347acc22cb17e93-did_set_spelllang
 * @id cpp/vim/c3d27ada14acd02db357f2d16347acc22cb17e93/did-set-spelllang
 * @description vim-c3d27ada14acd02db357f2d16347acc22cb17e93-src/spell.c-did_set_spelllang CVE-2022-4292
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwp_1990, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("win_valid_any_tab")
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwp_1990
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vbufref_2014, BlockStmt target_2, NotExpr target_1) {
		target_1.getOperand().(FunctionCall).getTarget().hasName("bufref_valid")
		and target_1.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbufref_2014
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_2.getStmt(1).(GotoStmt).getName() ="theend"
}

predicate func_3(Parameter vwp_1990, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="b_cjk"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_s"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_1990
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_4(Parameter vwp_1990, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("use_midword")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vwp_1990
}

from Function func, Variable vbufref_2014, Parameter vwp_1990, NotExpr target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vwp_1990, target_2, target_3, target_4)
and func_1(vbufref_2014, target_2, target_1)
and func_2(target_2)
and func_3(vwp_1990, target_3)
and func_4(vwp_1990, target_4)
and vbufref_2014.getType().hasName("bufref_T")
and vwp_1990.getType().hasName("win_T *")
and vbufref_2014.getParentScope+() = func
and vwp_1990.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
