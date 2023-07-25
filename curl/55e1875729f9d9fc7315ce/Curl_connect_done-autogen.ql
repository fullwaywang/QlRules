/**
 * @name curl-55e1875729f9d9fc7315ce-Curl_connect_done
 * @id cpp/curl/55e1875729f9d9fc7315ce/Curl-connect-done
 * @description curl-55e1875729f9d9fc7315ce-Curl_connect_done CVE-2022-42915
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vs_209) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof PointerFieldAccess
		and target_2.getThen() instanceof ExprStmt
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vs_209
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tunnel_state"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_209)
}

predicate func_3(Variable vs_209) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="prot_save"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_209
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vs_209
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tunnel_state"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_209)
}

from Function func, Parameter vdata_206, Variable vs_209
where
func_2(vs_209)
and func_3(vs_209)
and vdata_206.getType().hasName("Curl_easy *")
and vs_209.getType().hasName("http_connect_state *")
and vdata_206.getParentScope+() = func
and vs_209.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
