/**
 * @name linux-81f9c4e4177d31ced6f52a89bb70e93bfb77ca03-update_max_tr
 * @id cpp/linux/81f9c4e4177d31ced6f52a89bb70e93bfb77ca03/update-max-tr
 * @description linux-81f9c4e4177d31ced6f52a89bb70e93bfb77ca03-update_max_tr 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtr_1361, Variable vbuf_1363) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vbuf_1363
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="buffer"
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="max_buffer"
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtr_1361)
}

predicate func_2(Parameter vtr_1361, Function func) {
	exists(DoStmt target_2 |
		target_2.getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof ValueFieldAccess
		and target_2.getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="buffer"
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="max_buffer"
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtr_1361
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("ring_buffer *")
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_2))
}

predicate func_4(Parameter vtr_1361) {
	exists(ValueFieldAccess target_4 |
		target_4.getTarget().getName()="buffer"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="trace_buffer"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtr_1361)
}

predicate func_5(Parameter vtr_1361, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="buffer"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trace_buffer"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtr_1361
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="buffer"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="max_buffer"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtr_1361
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Variable vbuf_1363, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_1363
		and target_6.getExpr().(AssignExpr).getRValue() instanceof ValueFieldAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

from Function func, Parameter vtr_1361, Variable vbuf_1363
where
func_0(vtr_1361, vbuf_1363)
and not func_2(vtr_1361, func)
and func_4(vtr_1361)
and func_5(vtr_1361, func)
and func_6(vbuf_1363, func)
and vtr_1361.getType().hasName("trace_array *")
and vtr_1361.getParentScope+() = func
and vbuf_1363.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
