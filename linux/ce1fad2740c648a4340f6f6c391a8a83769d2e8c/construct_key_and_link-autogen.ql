/**
 * @name linux-ce1fad2740c648a4340f6f6c391a8a83769d2e8c-construct_key_and_link
 * @id cpp/linux/ce1fad2740c648a4340f6f6c391a8a83769d2e8c/construct-key-and-link
 * @description linux-ce1fad2740c648a4340f6f6c391a8a83769d2e8c-construct_key_and_link 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_430, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="index_key"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_430
		and target_0.getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("key_type")
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_PTR")
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

from Function func, Parameter vctx_430
where
not func_0(vctx_430, func)
and vctx_430.getType().hasName("keyring_search_context *")
and vctx_430.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
