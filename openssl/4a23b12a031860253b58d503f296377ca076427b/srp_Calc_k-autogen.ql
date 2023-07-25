/**
 * @name openssl-4a23b12a031860253b58d503f296377ca076427b-srp_Calc_k
 * @id cpp/openssl/4a23b12a031860253b58d503f296377ca076427b/srp-Calc-k
 * @description openssl-4a23b12a031860253b58d503f296377ca076427b-srp_Calc_k 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vg_82, Parameter vN_82, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_ucmp")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vg_82
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vN_82
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Variable vtmp_87, Variable vlongN_90) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmp_87
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CRYPTO_malloc")
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlongN_90
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_2(Parameter vN_82) {
	exists(DivExpr target_2 |
		target_2.getLeftOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_2.getLeftOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vN_82
		and target_2.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_2.getRightOperand().(Literal).getValue()="8")
}

from Function func, Parameter vg_82, Variable vtmp_87, Variable vlongN_90, Parameter vN_82
where
not func_0(vg_82, vN_82, func)
and not func_1(vtmp_87, vlongN_90)
and vg_82.getType().hasName("BIGNUM *")
and vtmp_87.getType().hasName("unsigned char *")
and vlongN_90.getType().hasName("int")
and vN_82.getType().hasName("BIGNUM *")
and func_2(vN_82)
and vg_82.getParentScope+() = func
and vtmp_87.getParentScope+() = func
and vlongN_90.getParentScope+() = func
and vN_82.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
