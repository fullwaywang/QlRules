/**
 * @name tor-b0496d40197dd5b4fb7b694c1410082d4e34dda6-time_delta_stalled_or_jumped
 * @id cpp/tor/b0496d40197dd5b4fb7b694c1410082d4e34dda6/time-delta-stalled-or-jumped
 * @description tor-b0496d40197dd5b4fb7b694c1410082d4e34dda6-src/core/or/congestion_control_common.c-time_delta_stalled_or_jumped CVE-2022-33903
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnew_delta_729, Variable v__FUNCTION__, Variable vdec_notice_limit_781, Parameter vold_delta_729, RelationalOperation target_8, ExprStmt target_7, Literal target_0) {
		target_0.getValue()="5"
		and not target_0.getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("log_fn_ratelim_")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdec_notice_limit_781
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="1024"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__FUNCTION__
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Sudden increase in circuit RTT (%lu vs %lu), likely due to clock jump."
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vnew_delta_729
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(DivExpr).getRightOperand().(Literal).getValue()="1000"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vold_delta_729
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(DivExpr).getRightOperand().(Literal).getValue()="1000"
		and target_8.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(DivExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
}

/*predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="Sudden increase in circuit RTT (%lu vs %lu), likely due to clock jump."
		and not target_1.getValue()="Sudden increase in circuit RTT (%lu vs %lu), likely due to clock jump or suspended remote endpoint."
		and target_1.getEnclosingFunction() = func
}

*/
predicate func_2(Function func) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("get_protocol_warning_severity_level")
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vis_monotime_clock_broken, EqualityOperation target_23, ReturnStmt target_3) {
		target_3.getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

predicate func_4(Parameter vcc_728, BlockStmt target_24, NotExpr target_4) {
		target_4.getOperand().(FunctionCall).getTarget().hasName("time_delta_should_use_heuristics")
		and target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcc_728
		and target_4.getParent().(IfStmt).getThen()=target_24
}

predicate func_5(Parameter vnew_delta_729, Parameter vold_delta_729, BlockStmt target_25, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vold_delta_729
		and target_5.getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnew_delta_729
		and target_5.getLesserOperand().(MulExpr).getRightOperand().(Literal).getValue()="5000"
		and target_5.getParent().(IfStmt).getThen()=target_25
}

predicate func_6(RelationalOperation target_5, Function func, DeclStmt target_6) {
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter vnew_delta_729, Variable v__FUNCTION__, Variable vdec_notice_limit_767, Parameter vold_delta_729, RelationalOperation target_5, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("log_fn_ratelim_")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdec_notice_limit_767
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="5"
		and target_7.getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="1024"
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__FUNCTION__
		and target_7.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Sudden decrease in circuit RTT (%lu vs %lu), likely due to clock jump."
		and target_7.getExpr().(FunctionCall).getArgument(5).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vnew_delta_729
		and target_7.getExpr().(FunctionCall).getArgument(5).(DivExpr).getRightOperand().(Literal).getValue()="1000"
		and target_7.getExpr().(FunctionCall).getArgument(6).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vold_delta_729
		and target_7.getExpr().(FunctionCall).getArgument(6).(DivExpr).getRightOperand().(Literal).getValue()="1000"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_8(Parameter vnew_delta_729, Parameter vold_delta_729, BlockStmt target_26, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getGreaterOperand().(VariableAccess).getTarget()=vnew_delta_729
		and target_8.getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vold_delta_729
		and target_8.getLesserOperand().(MulExpr).getRightOperand().(Literal).getValue()="5000"
		and target_8.getParent().(IfStmt).getThen()=target_26
}

predicate func_9(RelationalOperation target_8, Function func, DeclStmt target_9) {
		target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getEnclosingFunction() = func
}

predicate func_13(Parameter vold_delta_729, BlockStmt target_27, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vold_delta_729
		and target_13.getAnOperand() instanceof Literal
		and target_13.getParent().(IfStmt).getThen()=target_27
}

predicate func_14(Variable vis_monotime_clock_broken, ReturnStmt target_3, ReturnStmt target_28, VariableAccess target_14) {
		target_14.getTarget()=vis_monotime_clock_broken
		and target_3.getExpr().(VariableAccess).getLocation().isBefore(target_14.getLocation())
		and target_14.getLocation().isBefore(target_28.getExpr().(VariableAccess).getLocation())
}

predicate func_15(Variable vis_monotime_clock_broken, ReturnStmt target_29, VariableAccess target_15) {
		target_15.getTarget()=vis_monotime_clock_broken
		and target_29.getExpr().(VariableAccess).getLocation().isBefore(target_15.getLocation())
}

predicate func_16(Variable vis_monotime_clock_broken, ReturnStmt target_28, ReturnStmt target_30, AssignExpr target_16) {
		target_16.getLValue().(VariableAccess).getTarget()=vis_monotime_clock_broken
		and target_16.getRValue() instanceof Literal
		and target_28.getExpr().(VariableAccess).getLocation().isBefore(target_16.getLValue().(VariableAccess).getLocation())
		and target_16.getLValue().(VariableAccess).getLocation().isBefore(target_30.getExpr().(VariableAccess).getLocation())
}

predicate func_17(Variable vis_monotime_clock_broken, VariableAccess target_17) {
		target_17.getTarget()=vis_monotime_clock_broken
}

predicate func_18(Parameter vnew_delta_729, Variable v__FUNCTION__, Variable vis_monotime_clock_broken, Variable vdec_notice_limit_781, Parameter vold_delta_729, Function func, IfStmt target_18) {
		target_18.getCondition() instanceof RelationalOperation
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("log_fn_ratelim_")
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdec_notice_limit_781
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="1024"
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__FUNCTION__
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vnew_delta_729
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(DivExpr).getRightOperand().(Literal).getValue()="1000"
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vold_delta_729
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(DivExpr).getRightOperand().(Literal).getValue()="1000"
		and target_18.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_monotime_clock_broken
		and target_18.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_18.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

/*predicate func_19(Parameter vnew_delta_729, Variable v__FUNCTION__, Variable vdec_notice_limit_781, Parameter vold_delta_729, RelationalOperation target_8, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("log_fn_ratelim_")
		and target_19.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdec_notice_limit_781
		and target_19.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_19.getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="1024"
		and target_19.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__FUNCTION__
		and target_19.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_19.getExpr().(FunctionCall).getArgument(5).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vnew_delta_729
		and target_19.getExpr().(FunctionCall).getArgument(5).(DivExpr).getRightOperand().(Literal).getValue()="1000"
		and target_19.getExpr().(FunctionCall).getArgument(6).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vold_delta_729
		and target_19.getExpr().(FunctionCall).getArgument(6).(DivExpr).getRightOperand().(Literal).getValue()="1000"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

*/
predicate func_20(Variable vis_monotime_clock_broken, RelationalOperation target_8, ReturnStmt target_30, ReturnStmt target_32, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_monotime_clock_broken
		and target_20.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_30.getExpr().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_32.getExpr().(VariableAccess).getLocation())
}

/*predicate func_21(Variable vis_monotime_clock_broken, ExprStmt target_20, VariableAccess target_21) {
		target_21.getTarget()=vis_monotime_clock_broken
		and target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_21.getLocation())
}

*/
predicate func_22(Variable vis_monotime_clock_broken, ExprStmt target_33, Function func, ReturnStmt target_22) {
		target_22.getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22
		and target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_22.getExpr().(VariableAccess).getLocation())
}

predicate func_23(Parameter vnew_delta_729, EqualityOperation target_23) {
		target_23.getAnOperand().(VariableAccess).getTarget()=vnew_delta_729
		and target_23.getAnOperand().(Literal).getValue()="0"
}

predicate func_24(Variable vis_monotime_clock_broken, BlockStmt target_24) {
		target_24.getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
}

predicate func_25(Variable vis_monotime_clock_broken, BlockStmt target_25) {
		target_25.getStmt(1) instanceof ExprStmt
		and target_25.getStmt(2).(ExprStmt).getExpr() instanceof AssignExpr
		and target_25.getStmt(3).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
}

predicate func_26(Variable vis_monotime_clock_broken, BlockStmt target_26) {
		target_26.getStmt(1) instanceof ExprStmt
		and target_26.getStmt(2) instanceof ExprStmt
		and target_26.getStmt(3).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
}

predicate func_27(Variable vis_monotime_clock_broken, BlockStmt target_27) {
		target_27.getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
}

predicate func_28(Variable vis_monotime_clock_broken, ReturnStmt target_28) {
		target_28.getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
}

predicate func_29(Variable vis_monotime_clock_broken, ReturnStmt target_29) {
		target_29.getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
}

predicate func_30(Variable vis_monotime_clock_broken, ReturnStmt target_30) {
		target_30.getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
}

predicate func_32(Variable vis_monotime_clock_broken, ReturnStmt target_32) {
		target_32.getExpr().(VariableAccess).getTarget()=vis_monotime_clock_broken
}

predicate func_33(Variable vis_monotime_clock_broken, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_monotime_clock_broken
		and target_33.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vnew_delta_729, Variable v__FUNCTION__, Variable vis_monotime_clock_broken, Variable vdec_notice_limit_767, Variable vdec_notice_limit_781, Parameter vcc_728, Parameter vold_delta_729, Literal target_0, ReturnStmt target_3, NotExpr target_4, RelationalOperation target_5, DeclStmt target_6, ExprStmt target_7, RelationalOperation target_8, DeclStmt target_9, EqualityOperation target_13, VariableAccess target_14, VariableAccess target_15, AssignExpr target_16, VariableAccess target_17, IfStmt target_18, ExprStmt target_20, ReturnStmt target_22, EqualityOperation target_23, BlockStmt target_24, BlockStmt target_25, BlockStmt target_26, BlockStmt target_27, ReturnStmt target_28, ReturnStmt target_29, ReturnStmt target_30, ReturnStmt target_32, ExprStmt target_33
where
func_0(vnew_delta_729, v__FUNCTION__, vdec_notice_limit_781, vold_delta_729, target_8, target_7, target_0)
and not func_2(func)
and func_3(vis_monotime_clock_broken, target_23, target_3)
and func_4(vcc_728, target_24, target_4)
and func_5(vnew_delta_729, vold_delta_729, target_25, target_5)
and func_6(target_5, func, target_6)
and func_7(vnew_delta_729, v__FUNCTION__, vdec_notice_limit_767, vold_delta_729, target_5, target_7)
and func_8(vnew_delta_729, vold_delta_729, target_26, target_8)
and func_9(target_8, func, target_9)
and func_13(vold_delta_729, target_27, target_13)
and func_14(vis_monotime_clock_broken, target_3, target_28, target_14)
and func_15(vis_monotime_clock_broken, target_29, target_15)
and func_16(vis_monotime_clock_broken, target_28, target_30, target_16)
and func_17(vis_monotime_clock_broken, target_17)
and func_18(vnew_delta_729, v__FUNCTION__, vis_monotime_clock_broken, vdec_notice_limit_781, vold_delta_729, func, target_18)
and func_20(vis_monotime_clock_broken, target_8, target_30, target_32, target_20)
and func_22(vis_monotime_clock_broken, target_33, func, target_22)
and func_23(vnew_delta_729, target_23)
and func_24(vis_monotime_clock_broken, target_24)
and func_25(vis_monotime_clock_broken, target_25)
and func_26(vis_monotime_clock_broken, target_26)
and func_27(vis_monotime_clock_broken, target_27)
and func_28(vis_monotime_clock_broken, target_28)
and func_29(vis_monotime_clock_broken, target_29)
and func_30(vis_monotime_clock_broken, target_30)
and func_32(vis_monotime_clock_broken, target_32)
and func_33(vis_monotime_clock_broken, target_33)
and vnew_delta_729.getType().hasName("uint64_t")
and v__FUNCTION__.getType() instanceof ArrayType
and vis_monotime_clock_broken.getType().hasName("bool")
and vdec_notice_limit_767.getType().hasName("ratelim_t")
and vdec_notice_limit_781.getType().hasName("ratelim_t")
and vcc_728.getType().hasName("const congestion_control_t *")
and vold_delta_729.getType().hasName("uint64_t")
and vnew_delta_729.getParentScope+() = func
and not v__FUNCTION__.getParentScope+() = func
and not vis_monotime_clock_broken.getParentScope+() = func
and vdec_notice_limit_767.getParentScope+() = func
and vdec_notice_limit_781.getParentScope+() = func
and vcc_728.getParentScope+() = func
and vold_delta_729.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
