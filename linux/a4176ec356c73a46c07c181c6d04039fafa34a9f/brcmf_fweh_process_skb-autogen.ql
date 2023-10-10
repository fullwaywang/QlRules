/**
 * @name linux-a4176ec356c73a46c07c181c6d04039fafa34a9f-brcmf_fweh_process_skb
 * @id cpp/linux/a4176ec356c73a46c07c181c6d04039fafa34a9f/brcmf-fweh-process-skb
 * @description linux-a4176ec356c73a46c07c181c6d04039fafa34a9f-brcmf_fweh_process_skb 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vevent_packet_339, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("u16")
		and target_1.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u16")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_unaligned_be16")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="subtype"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hdr"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevent_packet_339
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("u16")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("u16")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_4(Parameter vskb_337, Variable vevent_packet_339) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vevent_packet_339
		and target_4.getRValue().(FunctionCall).getTarget().hasName("skb_mac_header")
		and target_4.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_337)
}

from Function func, Parameter vskb_337, Variable vevent_packet_339
where
not func_1(vevent_packet_339, func)
and vevent_packet_339.getType().hasName("brcmf_event *")
and func_4(vskb_337, vevent_packet_339)
and vskb_337.getParentScope+() = func
and vevent_packet_339.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
