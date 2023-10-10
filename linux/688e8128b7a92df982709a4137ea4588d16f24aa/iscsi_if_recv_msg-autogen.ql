/**
 * @name linux-688e8128b7a92df982709a4137ea4588d16f24aa-iscsi_if_recv_msg
 * @id cpp/linux/688e8128b7a92df982709a4137ea4588d16f24aa/iscsi_if_recv_msg
 * @description linux-688e8128b7a92df982709a4137ea4588d16f24aa-iscsi_if_recv_msg 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vskb_3613, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("netlink_capable")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_3613
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="21"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

from Function func, Parameter vskb_3613
where
not func_0(vskb_3613, func)
and vskb_3613.getType().hasName("sk_buff *")
and vskb_3613.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
