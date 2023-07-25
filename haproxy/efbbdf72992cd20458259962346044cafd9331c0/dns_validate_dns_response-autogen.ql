/**
 * @name haproxy-efbbdf72992cd20458259962346044cafd9331c0-dns_validate_dns_response
 * @id cpp/haproxy/efbbdf72992cd20458259962346044cafd9331c0/dns-validate-dns-response
 * @description haproxy-efbbdf72992cd20458259962346044cafd9331c0-src/dns.c-dns_validate_dns_response CVE-2018-20102
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vreader_609, Variable vdns_answer_record_615, Variable vdns_answer_item_pool, Parameter vbufend_606, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, SwitchStmt target_4, ExprStmt target_5, ExprStmt target_6, RelationalOperation target_7, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vreader_609
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdns_answer_record_615
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbufend_606
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pool_free")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdns_answer_item_pool
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdns_answer_record_615
		and target_1.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vreader_609, ExprStmt target_1) {
		target_1.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vreader_609
		and target_1.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_2(Variable vreader_609, Variable vdns_answer_record_615, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sin_addr"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="address"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdns_answer_record_615
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vreader_609
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data_len"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdns_answer_record_615
}

predicate func_3(Variable vreader_609, Variable vdns_answer_record_615, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdns_answer_record_615
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vreader_609
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="256"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vreader_609
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_4(Variable vdns_answer_record_615, Variable vdns_answer_item_pool, SwitchStmt target_4) {
		target_4.getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_4.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdns_answer_record_615
		and target_4.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="1"
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdns_answer_record_615
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pool_free")
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdns_answer_item_pool
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdns_answer_record_615
}

predicate func_5(Variable vdns_answer_record_615, Variable vdns_answer_item_pool, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("pool_free")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdns_answer_item_pool
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdns_answer_record_615
}

predicate func_6(Variable vdns_answer_record_615, Variable vdns_answer_item_pool, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("pool_free")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdns_answer_item_pool
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdns_answer_record_615
}

predicate func_7(Variable vreader_609, Parameter vbufend_606, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vreader_609
		and target_7.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vbufend_606
}

predicate func_8(Variable vreader_609, Parameter vbufend_606, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dns_read_name")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbufend_606
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vreader_609
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="255"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(Literal).getValue()="0"
}

from Function func, Variable vreader_609, Variable vdns_answer_record_615, Variable vdns_answer_item_pool, Parameter vbufend_606, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, SwitchStmt target_4, ExprStmt target_5, ExprStmt target_6, RelationalOperation target_7, ExprStmt target_8
where
not func_0(vreader_609, vdns_answer_record_615, vdns_answer_item_pool, vbufend_606, target_1, target_2, target_3, target_4, target_5, target_6, target_7, target_8)
and func_1(vreader_609, target_1)
and func_2(vreader_609, vdns_answer_record_615, target_2)
and func_3(vreader_609, vdns_answer_record_615, target_3)
and func_4(vdns_answer_record_615, vdns_answer_item_pool, target_4)
and func_5(vdns_answer_record_615, vdns_answer_item_pool, target_5)
and func_6(vdns_answer_record_615, vdns_answer_item_pool, target_6)
and func_7(vreader_609, vbufend_606, target_7)
and func_8(vreader_609, vbufend_606, target_8)
and vreader_609.getType().hasName("unsigned char *")
and vdns_answer_record_615.getType().hasName("dns_answer_item *")
and vdns_answer_item_pool.getType().hasName("pool_head *")
and vbufend_606.getType().hasName("unsigned char *")
and vreader_609.getParentScope+() = func
and vdns_answer_record_615.getParentScope+() = func
and not vdns_answer_item_pool.getParentScope+() = func
and vbufend_606.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
