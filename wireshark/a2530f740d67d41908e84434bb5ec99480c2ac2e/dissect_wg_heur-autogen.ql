/**
 * @name wireshark-a2530f740d67d41908e84434bb5ec99480c2ac2e-dissect_wg_heur
 * @id cpp/wireshark/a2530f740d67d41908e84434bb5ec99480c2ac2e/dissect-wg-heur
 * @description wireshark-a2530f740d67d41908e84434bb5ec99480c2ac2e-epan/dissectors/packet-wireguard.c-dissect_wg_heur CVE-2020-9429
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmessage_type_1647, SwitchStmt target_16, EqualityOperation target_17) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("wg_is_valid_message_length")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vmessage_type_1647
		and target_0.getArgument(1) instanceof FunctionCall
		and target_16.getExpr().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtvb_1635, FunctionCall target_1) {
		target_1.getTarget().hasName("tvb_reported_length")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vtvb_1635
}

predicate func_2(EqualityOperation target_18, Function func, ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getCondition()=target_18
		and target_2.getEnclosingFunction() = func
}

predicate func_4(ReturnStmt target_19, Function func, EqualityOperation target_4) {
		target_4.getAnOperand() instanceof FunctionCall
		and target_4.getAnOperand().(Literal).getValue()="148"
		and target_4.getParent().(IfStmt).getThen()=target_19
		and target_4.getEnclosingFunction() = func
}

predicate func_6(Parameter vtvb_1635, VariableAccess target_20, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("tvb_reported_length")
		and target_6.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_1635
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="92"
		and target_6.getThen() instanceof ReturnStmt
		and target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_20
}

predicate func_7(VariableAccess target_20, Function func, BreakStmt target_7) {
		target_7.toString() = "break;"
		and target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_20
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Parameter vtvb_1635, VariableAccess target_20, IfStmt target_8) {
		target_8.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("tvb_reported_length")
		and target_8.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_1635
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="64"
		and target_8.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_20
}

predicate func_9(VariableAccess target_20, Function func, BreakStmt target_9) {
		target_9.toString() = "break;"
		and target_9.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_20
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Parameter vtvb_1635, VariableAccess target_20, IfStmt target_10) {
		target_10.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("tvb_reported_length")
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_1635
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="32"
		and target_10.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_20
}

predicate func_11(Variable vreserved_is_zeroes_1648, VariableAccess target_20, IfStmt target_11) {
		target_11.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vreserved_is_zeroes_1648
		and target_11.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_20
}

/*predicate func_12(Variable vreserved_is_zeroes_1648, ReturnStmt target_21, NotExpr target_22, VariableAccess target_12) {
		target_12.getTarget()=vreserved_is_zeroes_1648
		and target_12.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_21
		and target_22.getOperand().(VariableAccess).getLocation().isBefore(target_12.getLocation())
}

*/
predicate func_13(VariableAccess target_20, Function func, BreakStmt target_13) {
		target_13.toString() = "break;"
		and target_13.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_20
		and target_13.getEnclosingFunction() = func
}

predicate func_14(Function func, SwitchCase target_14) {
		target_14.toString() = "default: "
		and target_14.getEnclosingFunction() = func
}

predicate func_15(VariableAccess target_20, Function func, ReturnStmt target_15) {
		target_15.getExpr().(Literal).getValue()="0"
		and target_15.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_20
		and target_15.getEnclosingFunction() = func
}

predicate func_16(Variable vmessage_type_1647, SwitchStmt target_16) {
		target_16.getExpr().(VariableAccess).getTarget()=vmessage_type_1647
		and target_16.getStmt().(BlockStmt).getStmt(0) instanceof SwitchCase
		and target_16.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition() instanceof EqualityOperation
		and target_16.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_16.getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_16.getStmt().(BlockStmt).getStmt(3) instanceof SwitchCase
}

predicate func_17(Variable vmessage_type_1647, EqualityOperation target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vmessage_type_1647
}

predicate func_18(EqualityOperation target_18) {
		target_18.getAnOperand() instanceof FunctionCall
		and target_18.getAnOperand() instanceof Literal
}

predicate func_19(ReturnStmt target_19) {
		target_19.getExpr().(Literal).getValue()="0"
}

predicate func_20(Variable vmessage_type_1647, VariableAccess target_20) {
		target_20.getTarget()=vmessage_type_1647
}

predicate func_21(ReturnStmt target_21) {
		target_21.getExpr() instanceof Literal
}

predicate func_22(Variable vreserved_is_zeroes_1648, NotExpr target_22) {
		target_22.getOperand().(VariableAccess).getTarget()=vreserved_is_zeroes_1648
}

from Function func, Variable vmessage_type_1647, Variable vreserved_is_zeroes_1648, Parameter vtvb_1635, FunctionCall target_1, ReturnStmt target_2, EqualityOperation target_4, IfStmt target_6, BreakStmt target_7, IfStmt target_8, BreakStmt target_9, IfStmt target_10, IfStmt target_11, BreakStmt target_13, SwitchCase target_14, ReturnStmt target_15, SwitchStmt target_16, EqualityOperation target_17, EqualityOperation target_18, ReturnStmt target_19, VariableAccess target_20, ReturnStmt target_21, NotExpr target_22
where
not func_0(vmessage_type_1647, target_16, target_17)
and func_1(vtvb_1635, target_1)
and func_2(target_18, func, target_2)
and func_4(target_19, func, target_4)
and func_6(vtvb_1635, target_20, target_6)
and func_7(target_20, func, target_7)
and func_8(vtvb_1635, target_20, target_8)
and func_9(target_20, func, target_9)
and func_10(vtvb_1635, target_20, target_10)
and func_11(vreserved_is_zeroes_1648, target_20, target_11)
and func_13(target_20, func, target_13)
and func_14(func, target_14)
and func_15(target_20, func, target_15)
and func_16(vmessage_type_1647, target_16)
and func_17(vmessage_type_1647, target_17)
and func_18(target_18)
and func_19(target_19)
and func_20(vmessage_type_1647, target_20)
and func_21(target_21)
and func_22(vreserved_is_zeroes_1648, target_22)
and vmessage_type_1647.getType().hasName("guint32")
and vreserved_is_zeroes_1648.getType().hasName("gboolean")
and vtvb_1635.getType().hasName("tvbuff_t *")
and vmessage_type_1647.getParentScope+() = func
and vreserved_is_zeroes_1648.getParentScope+() = func
and vtvb_1635.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
