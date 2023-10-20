/**
 * @name wireshark-e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a-nfs_full_name_snoop
 * @id cpp/wireshark/e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a/nfs-full-name-snoop
 * @description wireshark-e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a-epan/dissectors/packet-nfs.c-nfs_full_name_snoop CVE-2020-13164
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnns_1204, VariableAccess target_9, ExprStmt target_10, ExprStmt target_11) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PrefixIncrExpr).getOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="100"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fs_cycle"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnns_1204
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(NotExpr).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vnns_1204, ExprStmt target_10, ExprStmt target_11) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="fs_cycle"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnns_1204
		and target_1.getRValue().(NotExpr).getValue()="1"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_2(VariableAccess target_9, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("p_add_proto_data")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("packet_info *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("packet_info *")
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("unsigned int")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vlen_1204, Parameter vname_1204, Parameter vpos_1204, Variable vparent_nns_1206, VariableAccess target_9, ExprStmt target_12, SubExpr target_13, PointerDereferenceExpr target_14, ExprStmt target_11, IfStmt target_15) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("nfs_full_name_snoop")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("packet_info *")
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vparent_nns_1206
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_1204
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vname_1204
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vpos_1204
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_12.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_13.getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_14.getOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignPointerAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_15.getCondition().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_5(VariableAccess target_9, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(VariableAccess target_9, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("p_add_proto_data")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("packet_info *")
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("packet_info *")
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int")
		and target_6.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("unsigned int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(VariableAccess target_9, Function func) {
	exists(ReturnStmt target_7 |
		target_7.toString() = "return ..."
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(VariableAccess target_9, Function func, ReturnStmt target_8) {
		target_8.toString() = "return ..."
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vparent_nns_1206, VariableAccess target_9) {
		target_9.getTarget()=vparent_nns_1206
}

predicate func_10(Parameter vnns_1204, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="fh"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="parent"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnns_1204
}

predicate func_11(Parameter vnns_1204, Parameter vlen_1204, Parameter vname_1204, Parameter vpos_1204, ExprStmt target_11) {
		target_11.getExpr().(AssignPointerAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpos_1204
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getTarget().hasName("g_snprintf")
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpos_1204
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlen_1204
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(PointerArithmeticOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpos_1204
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(PointerArithmeticOperation).getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vname_1204
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s%s"
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(StringLiteral).getValue()="/"
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="name"
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnns_1204
}

predicate func_12(Parameter vlen_1204, Parameter vname_1204, Parameter vpos_1204, ExprStmt target_12) {
		target_12.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpos_1204
		and target_12.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vname_1204
		and target_12.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlen_1204
		and target_12.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_12.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("proto_report_dissector_bug")
		and target_12.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s:%u: failed assertion \"%s\""
		and target_12.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_12.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(2) instanceof Literal
		and target_12.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(3).(StringLiteral).getValue()="(*pos-*name) <= *len"
}

predicate func_13(Parameter vlen_1204, Parameter vname_1204, Parameter vpos_1204, SubExpr target_13) {
		target_13.getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlen_1204
		and target_13.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_13.getRightOperand().(PointerArithmeticOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpos_1204
		and target_13.getRightOperand().(PointerArithmeticOperation).getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vname_1204
}

predicate func_14(Parameter vname_1204, PointerDereferenceExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vname_1204
}

predicate func_15(Parameter vlen_1204, Parameter vname_1204, Parameter vpos_1204, Variable vparent_nns_1206, IfStmt target_15) {
		target_15.getCondition().(VariableAccess).getTarget()=vparent_nns_1206
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("nfs_full_name_snoop")
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparent_nns_1206
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_1204
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vname_1204
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpos_1204
}

from Function func, Parameter vnns_1204, Parameter vlen_1204, Parameter vname_1204, Parameter vpos_1204, Variable vparent_nns_1206, ReturnStmt target_8, VariableAccess target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, SubExpr target_13, PointerDereferenceExpr target_14, IfStmt target_15
where
not func_0(vnns_1204, target_9, target_10, target_11)
and not func_2(target_9, func)
and not func_3(vlen_1204, vname_1204, vpos_1204, vparent_nns_1206, target_9, target_12, target_13, target_14, target_11, target_15)
and not func_5(target_9, func)
and not func_6(target_9, func)
and not func_7(target_9, func)
and func_8(target_9, func, target_8)
and func_9(vparent_nns_1206, target_9)
and func_10(vnns_1204, target_10)
and func_11(vnns_1204, vlen_1204, vname_1204, vpos_1204, target_11)
and func_12(vlen_1204, vname_1204, vpos_1204, target_12)
and func_13(vlen_1204, vname_1204, vpos_1204, target_13)
and func_14(vname_1204, target_14)
and func_15(vlen_1204, vname_1204, vpos_1204, vparent_nns_1206, target_15)
and vnns_1204.getType().hasName("nfs_name_snoop_t *")
and vlen_1204.getType().hasName("int *")
and vname_1204.getType().hasName("char **")
and vpos_1204.getType().hasName("char **")
and vparent_nns_1206.getType().hasName("nfs_name_snoop_t *")
and vnns_1204.getParentScope+() = func
and vlen_1204.getParentScope+() = func
and vname_1204.getParentScope+() = func
and vpos_1204.getParentScope+() = func
and vparent_nns_1206.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
