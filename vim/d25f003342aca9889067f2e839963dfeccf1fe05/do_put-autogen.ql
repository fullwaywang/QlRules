/**
 * @name vim-d25f003342aca9889067f2e839963dfeccf1fe05-do_put
 * @id cpp/vim/d25f003342aca9889067f2e839963dfeccf1fe05/do-put
 * @description vim-d25f003342aca9889067f2e839963dfeccf1fe05-src/register.c-do_put CVE-2022-2264
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtotlen_1535, Variable vspaces_1823, LogicalAndExpr target_1, AddExpr target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vtotlen_1535
		and target_0.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vspaces_1823
		and target_0.getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vspaces_1823, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(VariableAccess).getTarget()=vspaces_1823
}

predicate func_2(Variable vtotlen_1535, AddExpr target_2) {
		target_2.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtotlen_1535
		and target_2.getAnOperand().(Literal).getValue()="1"
}

predicate func_3(Variable vtotlen_1535, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="textcol"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtotlen_1535
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_4(Variable vspaces_1823, ExprStmt target_4) {
		target_4.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vspaces_1823
}

from Function func, Variable vtotlen_1535, Variable vspaces_1823, LogicalAndExpr target_1, AddExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vtotlen_1535, vspaces_1823, target_1, target_2, target_3, target_4)
and func_1(vspaces_1823, target_1)
and func_2(vtotlen_1535, target_2)
and func_3(vtotlen_1535, target_3)
and func_4(vspaces_1823, target_4)
and vtotlen_1535.getType().hasName("int")
and vspaces_1823.getType().hasName("int")
and vtotlen_1535.getParentScope+() = func
and vspaces_1823.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
