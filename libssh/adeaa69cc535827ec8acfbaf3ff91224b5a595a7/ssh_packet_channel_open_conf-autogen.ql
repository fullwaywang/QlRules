/**
 * @name libssh-adeaa69cc535827ec8acfbaf3ff91224b5a595a7-ssh_packet_channel_open_conf
 * @id cpp/libssh/adeaa69cc535827ec8acfbaf3ff91224b5a595a7/ssh-packet-channel-open-conf
 * @description libssh-adeaa69cc535827ec8acfbaf3ff91224b5a595a7-src/channels.c-ssh_packet_channel_open_conf CVE-2018-10933
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vchannel_143, Variable v__func__, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_143
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_ssh_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SSH2_MSG_CHANNEL_OPEN_CONFIRMATION received in incorrect channel state %d"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_143
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="error"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vchannel_143, Variable v__func__, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("_ssh_log")
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Received a CHANNEL_OPEN_CONFIRMATION for channel %d:%d"
		and target_1.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="local_channel"
		and target_1.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_143
		and target_1.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="remote_channel"
		and target_1.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_143
}

predicate func_2(Variable vchannel_143, Variable v__func__, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("_ssh_log")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Remote window : %lu, maxpacket : %lu"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="remote_window"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_143
		and target_2.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="remote_maxpacket"
		and target_2.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_143
}

from Function func, Variable vchannel_143, Variable v__func__, ExprStmt target_1, ExprStmt target_2
where
not func_0(vchannel_143, v__func__, target_1, target_2, func)
and func_1(vchannel_143, v__func__, target_1)
and func_2(vchannel_143, v__func__, target_2)
and vchannel_143.getType().hasName("ssh_channel")
and v__func__.getType() instanceof ArrayType
and vchannel_143.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
