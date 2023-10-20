/**
 * @name cjson-d514bb866ef9d7d8ab394fbce5168c3b45f7c504-print_value
 * @id cpp/cjson/d514bb866ef9d7d8ab394fbce5168c3b45f7c504/print-value
 * @description cjson-d514bb866ef9d7d8ab394fbce5168c3b45f7c504-cJSON.c-print_value CVE-2018-1000216
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voutput_buffer_1268, EqualityOperation target_2, IfStmt target_0) {
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="noalloc"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutput_buffer_1268
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="deallocate"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hooks"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutput_buffer_1268
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutput_buffer_1268
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

/*predicate func_1(Parameter voutput_buffer_1268, NotExpr target_3, ExprStmt target_1) {
		target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="deallocate"
		and target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hooks"
		and target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutput_buffer_1268
		and target_1.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_1.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutput_buffer_1268
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

*/
predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="valuestring"
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter voutput_buffer_1268, NotExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="noalloc"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutput_buffer_1268
}

from Function func, Parameter voutput_buffer_1268, IfStmt target_0, EqualityOperation target_2, NotExpr target_3
where
func_0(voutput_buffer_1268, target_2, target_0)
and func_2(target_2)
and func_3(voutput_buffer_1268, target_3)
and voutput_buffer_1268.getType().hasName("printbuffer *const")
and voutput_buffer_1268.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
