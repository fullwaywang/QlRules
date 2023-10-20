/**
 * @name ghostscript-4f73e8b4d578e69a17f452fa60d2130c5faaefd6-cdj_put_param_bpp
 * @id cpp/ghostscript/4f73e8b4d578e69a17f452fa60d2130c5faaefd6/cdj-put-param-bpp
 * @description ghostscript-4f73e8b4d578e69a17f452fa60d2130c5faaefd6-contrib/gdevdj9.c-cdj_put_param_bpp CVE-2020-16291
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Initializer target_0 |
		target_0.getExpr() instanceof Literal
		and target_0.getExpr().getEnclosingFunction() = func)
}

predicate func_1(Variable vcode_2605, LogicalAndExpr target_21) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_2605
		and target_1.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21)
}

predicate func_2(LogicalAndExpr target_22, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr() instanceof FunctionCall
		and target_2.getParent().(IfStmt).getCondition()=target_22
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vpdev_2596, Parameter vplist_2597, FunctionCall target_18, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="HWResolution"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="HWResolution"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="HWResolution"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="300.0"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="HWResolution"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="600.0"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="signal_error"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vplist_2597
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="HWResolution"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("emprintf_program_ident")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("gs_program_name")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("gs_revision_number")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errprintf")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\ncdj970: Invalid resolution: '%f'. Only 300 or 600 supported.\n\n"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="HWResolution"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cdj_set_bpp")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_2596
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="num_components"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("gx_device_color_info")
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_3)
		and target_18.getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vpdev_2596, Variable vsave_info_2603, LogicalAndExpr target_21, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsave_info_2603
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="color_info"
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_7(Variable vsave_info_2603, Variable vsave_bpp_2604, LogicalAndExpr target_21, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsave_bpp_2604
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="depth"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsave_info_2603
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_8(Parameter vpdev_2596, Variable vsave_info_2603, Variable vsave_bpp_2604, LogicalAndExpr target_21, IfStmt target_8) {
		target_8.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsave_bpp_2604
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="num_components"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsave_info_2603
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmyk"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsave_bpp_2604
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_9(Parameter vpdev_2596, Parameter vreal_bpp_2598, Parameter vccomps_2598, Variable vcode_2605, LogicalAndExpr target_21, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_2605
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdj_set_bpp")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_2596
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vreal_bpp_2598
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vccomps_2598
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_10(Parameter vplist_2597, Variable vcode_2605, LogicalAndExpr target_21, IfStmt target_10) {
		target_10.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcode_2605
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="signal_error"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vplist_2597
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="BitsPerPixel"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(VariableAccess).getTarget()=vcode_2605
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="signal_error"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vplist_2597
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="ProcessColorModel"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(ExprCall).getArgument(2).(VariableAccess).getTarget()=vcode_2605
		and target_10.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_2605
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_11(Parameter vpdev_2596, Parameter vnew_bpp_2598, LogicalAndExpr target_21, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="depth"
		and target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="color_info"
		and target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnew_bpp_2598
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_12(Parameter vpdev_2596, Parameter vplist_2597, Variable vcode_2605, LogicalAndExpr target_21, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_2605
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("gdev_prn_put_params")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_2596
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vplist_2597
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_13(Parameter vpdev_2596, Variable vsave_info_2603, Variable vsave_bpp_2604, Variable vcode_2605, LogicalAndExpr target_21, IfStmt target_13) {
		target_13.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcode_2605
		and target_13.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cdj_set_bpp")
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_2596
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsave_bpp_2604
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="num_components"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsave_info_2603
		and target_13.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_2605
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_14(Parameter vpdev_2596, Parameter vreal_bpp_2598, Parameter vccomps_2598, LogicalAndExpr target_21, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("cdj_set_bpp")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_2596
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vreal_bpp_2598
		and target_14.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vccomps_2598
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_15(Parameter vpdev_2596, Parameter vplist_2597, FunctionCall target_15) {
		target_15.getTarget().hasName("gdev_prn_put_params")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vpdev_2596
		and target_15.getArgument(1).(VariableAccess).getTarget()=vplist_2597
}

predicate func_16(LogicalAndExpr target_21, Function func, DeclStmt target_16) {
		target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_16.getEnclosingFunction() = func
}

predicate func_17(LogicalAndExpr target_21, Function func, DeclStmt target_17) {
		target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_17.getEnclosingFunction() = func
}

predicate func_18(Parameter vpdev_2596, FunctionCall target_18) {
		target_18.getTarget().hasName("gs_closedevice")
		and target_18.getArgument(0).(VariableAccess).getTarget()=vpdev_2596
}

predicate func_20(LogicalAndExpr target_21, Function func, ReturnStmt target_20) {
		target_20.getExpr() instanceof Literal
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_20.getEnclosingFunction() = func
}

predicate func_21(Parameter vnew_bpp_2598, Parameter vccomps_2598, LogicalAndExpr target_21) {
		target_21.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnew_bpp_2598
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vccomps_2598
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_22(Parameter vpdev_2596, Parameter vccomps_2598, Variable vsave_info_2603, Variable vsave_bpp_2604, LogicalAndExpr target_22) {
		target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="depth"
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="color_info"
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsave_bpp_2604
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vccomps_2598
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vccomps_2598
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="num_components"
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsave_info_2603
		and target_22.getAnOperand().(PointerFieldAccess).getTarget().getName()="is_open"
		and target_22.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2596
}

from Function func, Parameter vpdev_2596, Parameter vplist_2597, Parameter vnew_bpp_2598, Parameter vreal_bpp_2598, Parameter vccomps_2598, Variable vsave_info_2603, Variable vsave_bpp_2604, Variable vcode_2605, ExprStmt target_6, ExprStmt target_7, IfStmt target_8, ExprStmt target_9, IfStmt target_10, ExprStmt target_11, ExprStmt target_12, IfStmt target_13, ExprStmt target_14, FunctionCall target_15, DeclStmt target_16, DeclStmt target_17, FunctionCall target_18, ReturnStmt target_20, LogicalAndExpr target_21, LogicalAndExpr target_22
where
not func_0(func)
and not func_1(vcode_2605, target_21)
and not func_2(target_22, func)
and not func_3(vpdev_2596, vplist_2597, target_18, func)
and func_6(vpdev_2596, vsave_info_2603, target_21, target_6)
and func_7(vsave_info_2603, vsave_bpp_2604, target_21, target_7)
and func_8(vpdev_2596, vsave_info_2603, vsave_bpp_2604, target_21, target_8)
and func_9(vpdev_2596, vreal_bpp_2598, vccomps_2598, vcode_2605, target_21, target_9)
and func_10(vplist_2597, vcode_2605, target_21, target_10)
and func_11(vpdev_2596, vnew_bpp_2598, target_21, target_11)
and func_12(vpdev_2596, vplist_2597, vcode_2605, target_21, target_12)
and func_13(vpdev_2596, vsave_info_2603, vsave_bpp_2604, vcode_2605, target_21, target_13)
and func_14(vpdev_2596, vreal_bpp_2598, vccomps_2598, target_21, target_14)
and func_15(vpdev_2596, vplist_2597, target_15)
and func_16(target_21, func, target_16)
and func_17(target_21, func, target_17)
and func_18(vpdev_2596, target_18)
and func_20(target_21, func, target_20)
and func_21(vnew_bpp_2598, vccomps_2598, target_21)
and func_22(vpdev_2596, vccomps_2598, vsave_info_2603, vsave_bpp_2604, target_22)
and vpdev_2596.getType().hasName("gx_device *")
and vplist_2597.getType().hasName("gs_param_list *")
and vnew_bpp_2598.getType().hasName("int")
and vreal_bpp_2598.getType().hasName("int")
and vccomps_2598.getType().hasName("int")
and vsave_info_2603.getType().hasName("gx_device_color_info")
and vsave_bpp_2604.getType().hasName("int")
and vcode_2605.getType().hasName("int")
and vpdev_2596.getFunction() = func
and vplist_2597.getFunction() = func
and vnew_bpp_2598.getFunction() = func
and vreal_bpp_2598.getFunction() = func
and vccomps_2598.getFunction() = func
and vsave_info_2603.(LocalVariable).getFunction() = func
and vsave_bpp_2604.(LocalVariable).getFunction() = func
and vcode_2605.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
