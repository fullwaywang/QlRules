/**
 * @name ndpi-6a9f5e4f7c3fd5ddab3e6727b071904d76773952-ndpi_reset_packet_line_info
 * @id cpp/ndpi/6a9f5e4f7c3fd5ddab3e6727b071904d76773952/ndpi-reset-packet-line-info
 * @description ndpi-6a9f5e4f7c3fd5ddab3e6727b071904d76773952-src/lib/ndpi_main.c-ndpi_reset_packet_line_info CVE-2020-15475
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpacket_4332, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="http_cookie"
		and target_0.getQualifier().(VariableAccess).getTarget()=vpacket_4332
}

predicate func_1(Parameter vpacket_4332, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="http_cookie"
		and target_1.getQualifier().(VariableAccess).getTarget()=vpacket_4332
}

predicate func_2(Parameter vpacket_4332) {
	exists(CommaExpr target_2 |
		target_2.getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_2.getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ptr"
		and target_2.getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="content_disposition_line"
		and target_2.getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_2.getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="content_disposition_line"
		and target_2.getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_4332
		and target_2.getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getLeftOperand().(CommaExpr).getRightOperand() instanceof AssignExpr
		and target_2.getRightOperand() instanceof AssignExpr)
}

/*predicate func_3(Parameter vpacket_4332) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(ValueFieldAccess).getTarget().getName()="ptr"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="content_disposition_line"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_4332
		and target_3.getRValue().(Literal).getValue()="0")
}

*/
/*predicate func_4(Parameter vpacket_4332) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_4.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="content_disposition_line"
		and target_4.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_4332
		and target_4.getRValue().(Literal).getValue()="0")
}

*/
predicate func_5(Parameter vpacket_4332, AssignExpr target_5) {
		target_5.getLValue().(ValueFieldAccess).getTarget().getName()="ptr"
		and target_5.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_cookie"
		and target_5.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_4332
		and target_5.getRValue().(Literal).getValue()="0"
}

predicate func_6(Parameter vpacket_4332, AssignExpr target_6) {
		target_6.getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_6.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_cookie"
		and target_6.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_4332
		and target_6.getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vpacket_4332, PointerFieldAccess target_0, PointerFieldAccess target_1, AssignExpr target_5, AssignExpr target_6
where
func_0(vpacket_4332, target_0)
and func_1(vpacket_4332, target_1)
and not func_2(vpacket_4332)
and func_5(vpacket_4332, target_5)
and func_6(vpacket_4332, target_6)
and vpacket_4332.getType().hasName("ndpi_packet_struct *")
and vpacket_4332.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
