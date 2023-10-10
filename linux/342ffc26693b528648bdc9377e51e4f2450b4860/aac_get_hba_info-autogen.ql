/**
 * @name linux-342ffc26693b528648bdc9377e51e4f2450b4860-aac_get_hba_info
 * @id cpp/linux/342ffc26693b528648bdc9377e51e4f2450b4860/aac-get-hba-info
 * @description linux-342ffc26693b528648bdc9377e51e4f2450b4860-aac_get_hba_info 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhbainfo_1021, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhbainfo_1021
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="200"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vhbainfo_1021
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func, Variable vhbainfo_1021
where
not func_0(vhbainfo_1021, func)
and vhbainfo_1021.getType().hasName("aac_hba_info")
and vhbainfo_1021.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
