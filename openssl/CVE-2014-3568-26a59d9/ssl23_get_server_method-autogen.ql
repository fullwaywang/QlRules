/**
 * @name openssl-26a59d9b46574e457870197dffa802871b4c8fc7-ssl23_get_server_method
 * @id cpp/openssl/26a59d9b46574e457870197dffa802871b4c8fc7/ssl23-get-server-method
 * @description openssl-26a59d9b46574e457870197dffa802871b4c8fc7-ssl23_get_server_method CVE-2014-3568
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vver_124) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vver_124
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="769"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("TLSv1_server_method")
		and target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vver_124
		and target_0.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="770"
		and target_0.getElse().(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("TLSv1_1_server_method")
		and target_0.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vver_124
		and target_0.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="771"
		and target_0.getElse().(IfStmt).getElse().(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("TLSv1_2_server_method")
		and target_0.getElse().(IfStmt).getElse().(IfStmt).getElse().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vver_124
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="768")
}

from Function func, Parameter vver_124
where
func_0(vver_124)
and vver_124.getType().hasName("int")
and vver_124.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
