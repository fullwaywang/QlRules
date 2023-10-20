/**
 * @name openssl-4a23b12a031860253b58d503f296377ca076427b-SRP_Calc_u
 * @id cpp/openssl/4a23b12a031860253b58d503f296377ca076427b/SRP-Calc-u
 * @description openssl-4a23b12a031860253b58d503f296377ca076427b-SRP_Calc_u CVE-2014-3512
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vB_112, Parameter vN_112, Parameter vA_112, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_ucmp")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vA_112
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vN_112
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_ucmp")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vB_112
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vN_112
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vB_112, Parameter vN_112, Parameter vA_112) {
	exists(LogicalOrExpr target_3 |
		target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vA_112
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vB_112
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vN_112
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter vB_112, Parameter vN_112, Parameter vA_112
where
not func_0(vB_112, vN_112, vA_112, func)
and not func_1(func)
and vB_112.getType().hasName("BIGNUM *")
and func_3(vB_112, vN_112, vA_112)
and vN_112.getType().hasName("BIGNUM *")
and vA_112.getType().hasName("BIGNUM *")
and vB_112.getParentScope+() = func
and vN_112.getParentScope+() = func
and vA_112.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
