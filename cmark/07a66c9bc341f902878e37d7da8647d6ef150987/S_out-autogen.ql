/**
 * @name cmark-07a66c9bc341f902878e37d7da8647d6ef150987-S_out
 * @id cpp/cmark/07a66c9bc341f902878e37d7da8647d6ef150987/S-out
 * @description cmark-07a66c9bc341f902878e37d7da8647d6ef150987-src/render.c-S_out CVE-2023-26485
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vn_35, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="extension"
		and target_0.getQualifier().(VariableAccess).getTarget()=vn_35
}

predicate func_2(Function func, DeclStmt target_2) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vext_34, Variable vn_35, Function func, WhileStmt target_3) {
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vn_35
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vext_34
		and target_3.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vext_34
		and target_3.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="extension"
		and target_3.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_35
		and target_3.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vext_34
		and target_3.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_35
		and target_3.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="parent"
		and target_3.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_35
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

/*predicate func_4(Variable vext_34, Variable vn_35, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vext_34
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="extension"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_35
}

*/
/*predicate func_5(Variable vext_34, Variable vn_35, IfStmt target_5) {
		target_5.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vext_34
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_35
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="parent"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_35
}

*/
from Function func, Variable vext_34, Variable vn_35, PointerFieldAccess target_0, DeclStmt target_2, WhileStmt target_3
where
func_0(vn_35, target_0)
and func_2(func, target_2)
and func_3(vext_34, vn_35, func, target_3)
and vext_34.getType().hasName("cmark_syntax_extension *")
and vn_35.getType().hasName("cmark_node *")
and vext_34.getParentScope+() = func
and vn_35.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
