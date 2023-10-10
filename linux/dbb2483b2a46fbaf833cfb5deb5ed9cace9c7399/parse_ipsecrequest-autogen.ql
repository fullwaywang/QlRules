/**
 * @name linux-dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399-parse_ipsecrequest
 * @id cpp/linux/dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399/parse_ipsecrequest
 * @description linux-dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399-parse_ipsecrequest 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vrq_1943, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xfrm_id_proto_valid")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sadb_x_ipsecrequest_proto"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrq_1943
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vrq_1943) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="sadb_x_ipsecrequest_mode"
		and target_1.getQualifier().(VariableAccess).getTarget()=vrq_1943)
}

from Function func, Parameter vrq_1943
where
not func_0(vrq_1943, func)
and vrq_1943.getType().hasName("sadb_x_ipsecrequest *")
and func_1(vrq_1943)
and vrq_1943.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
