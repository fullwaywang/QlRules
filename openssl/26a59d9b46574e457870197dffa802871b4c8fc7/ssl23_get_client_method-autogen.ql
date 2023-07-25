/**
 * @name openssl-26a59d9b46574e457870197dffa802871b4c8fc7-ssl23_get_client_method
 * @id cpp/openssl/26a59d9b46574e457870197dffa802871b4c8fc7/ssl23-get-client-method
 * @description openssl-26a59d9b46574e457870197dffa802871b4c8fc7-ssl23_get_client_method CVE-2014-3568
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vver_122) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vver_122
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="769"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("TLSv1_client_method")
		and target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vver_122
		and target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="770"
		and target_0.getElse().(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("TLSv1_1_client_method")
		and target_0.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vver_122
		and target_0.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="771"
		and target_0.getElse().(IfStmt).getElse().(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("TLSv1_2_client_method")
		and target_0.getElse().(IfStmt).getElse().(IfStmt).getElse().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vver_122
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="768")
}

from Function func, Parameter vver_122
where
func_0(vver_122)
and vver_122.getType().hasName("int")
and vver_122.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
