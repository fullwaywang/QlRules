/**
 * @name libpcap-87d6bef033062f969e70fa40c43dfd945d5a20ab-pcap_ng_check_header
 * @id cpp/libpcap/87d6bef033062f969e70fa40c43dfd945d5a20ab/pcap-ng-check-header
 * @description libpcap-87d6bef033062f969e70fa40c43dfd945d5a20ab-sf-pcapng.c-pcap_ng_check_header CVE-2019-15165
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtotal_length_769, BlockStmt target_12, MulExpr target_0) {
		target_0.getValue()="16777216"
		and target_0.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vtotal_length_769
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_12
}

predicate func_1(Function func, MulExpr target_1) {
		target_1.getValue()="16777216"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="Section Header Block in pcapng dump file has a length of %u < %zu"
		and not target_2.getValue()="Section Header Block in pcapng dump file has invalid length %zu < _%lu_ < %lu (BT_SHB_INSANE_MAX)"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="256"
		and not target_3.getValue()="1024"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vtotal_length_769, BlockStmt target_13, ExprStmt target_14, ExprStmt target_11) {
	exists(LogicalOrExpr target_4 |
		target_4.getAnOperand() instanceof RelationalOperation
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtotal_length_769
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="1048576"
		and target_4.getParent().(IfStmt).getThen()=target_13
		and target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_5(Function func) {
	exists(MulExpr target_5 |
		target_5.getValue()="1048576"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func, MulExpr target_6) {
		target_6.getValue()="16384"
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter verr_765, RelationalOperation target_15, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verr_765
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_8(RelationalOperation target_15, Function func, ReturnStmt target_8) {
		target_8.getExpr().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vtotal_length_769, BlockStmt target_13, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vtotal_length_769
		and target_9.getGreaterOperand().(AddExpr).getValue()="28"
		and target_9.getParent().(IfStmt).getThen()=target_13
}

predicate func_10(Parameter verrbuf_765, Variable vtotal_length_769, Function func, IfStmt target_10) {
		target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtotal_length_769
		and target_10.getCondition().(RelationalOperation).getLesserOperand() instanceof MulExpr
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verrbuf_765
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pcapng block size %u > maximum %u"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtotal_length_769
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof MulExpr
		and target_10.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Parameter verrbuf_765, Variable vtotal_length_769, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verrbuf_765
		and target_11.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_11.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pcapng block size %u > maximum %u"
		and target_11.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtotal_length_769
		and target_11.getExpr().(FunctionCall).getArgument(4) instanceof MulExpr
}

predicate func_12(BlockStmt target_12) {
		target_12.getStmt(0) instanceof ExprStmt
		and target_12.getStmt(1) instanceof ExprStmt
		and target_12.getStmt(2) instanceof ReturnStmt
}

predicate func_13(Parameter verrbuf_765, Variable vtotal_length_769, BlockStmt target_13) {
		target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verrbuf_765
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="256"
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtotal_length_769
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getValue()="28"
}

predicate func_14(Parameter verrbuf_765, Variable vtotal_length_769, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verrbuf_765
		and target_14.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="256"
		and target_14.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtotal_length_769
		and target_14.getExpr().(FunctionCall).getArgument(4).(AddExpr).getValue()="28"
}

predicate func_15(Variable vtotal_length_769, RelationalOperation target_15) {
		 (target_15 instanceof GTExpr or target_15 instanceof LTExpr)
		and target_15.getGreaterOperand().(VariableAccess).getTarget()=vtotal_length_769
		and target_15.getLesserOperand() instanceof MulExpr
}

from Function func, Parameter verrbuf_765, Parameter verr_765, Variable vtotal_length_769, MulExpr target_0, MulExpr target_1, StringLiteral target_2, Literal target_3, MulExpr target_6, ExprStmt target_7, ReturnStmt target_8, RelationalOperation target_9, IfStmt target_10, ExprStmt target_11, BlockStmt target_12, BlockStmt target_13, ExprStmt target_14, RelationalOperation target_15
where
func_0(vtotal_length_769, target_12, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and not func_4(vtotal_length_769, target_13, target_14, target_11)
and not func_5(func)
and func_6(func, target_6)
and func_7(verr_765, target_15, target_7)
and func_8(target_15, func, target_8)
and func_9(vtotal_length_769, target_13, target_9)
and func_10(verrbuf_765, vtotal_length_769, func, target_10)
and func_11(verrbuf_765, vtotal_length_769, target_11)
and func_12(target_12)
and func_13(verrbuf_765, vtotal_length_769, target_13)
and func_14(verrbuf_765, vtotal_length_769, target_14)
and func_15(vtotal_length_769, target_15)
and verrbuf_765.getType().hasName("char *")
and verr_765.getType().hasName("int *")
and vtotal_length_769.getType().hasName("bpf_u_int32")
and verrbuf_765.getParentScope+() = func
and verr_765.getParentScope+() = func
and vtotal_length_769.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
