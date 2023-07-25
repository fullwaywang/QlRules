/**
 * @name dpdk-acd4c92fa693bbea695f2bb42bb93fb8567c3ca5-transform_chain_param
 * @id cpp/dpdk/acd4c92fa693bbea695f2bb42bb93fb8567c3ca5/transform-chain-param
 * @description dpdk-acd4c92fa693bbea695f2bb42bb93fb8567c3ca5-lib/librte_vhost/vhost_crypto.c-transform_chain_param CVE-2020-10724
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vparam_264, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="cipher_key_len"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_264
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="64"
		and target_0.getThen().(BlockStmt).getStmt(0).(EmptyStmt).toString() = ";"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-2"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vparam_264, ExprStmt target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="auth_key_len"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_264
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="512"
		and target_1.getThen().(BlockStmt).getStmt(0).(EmptyStmt).toString() = ";"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-2"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_1)
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vparam_264, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cipher_algo_transform")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cipher_algo"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_264
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="algo"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="cipher"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
}

predicate func_3(Parameter vparam_264, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="length"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="key"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="cipher"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="cipher_key_len"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_264
}

predicate func_4(Parameter vparam_264, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("auth_algo_transform")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="hash_algo"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_264
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="algo"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="auth"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
}

predicate func_5(Parameter vparam_264, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="digest_length"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="auth"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="digest_len"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_264
}

from Function func, Parameter vparam_264, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vparam_264, target_2, target_3, func)
and not func_1(vparam_264, target_4, target_5, func)
and func_2(vparam_264, target_2)
and func_3(vparam_264, target_3)
and func_4(vparam_264, target_4)
and func_5(vparam_264, target_5)
and vparam_264.getType().hasName("VhostUserCryptoSessionParam *")
and vparam_264.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
