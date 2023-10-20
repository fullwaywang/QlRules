/**
 * @name ghostscript-4f73e8b4d578e69a17f452fa60d2130c5faaefd6-cdj970_put_params
 * @id cpp/ghostscript/4f73e8b4d578e69a17f452fa60d2130c5faaefd6/cdj970-put-params
 * @description ghostscript-4f73e8b4d578e69a17f452fa60d2130c5faaefd6-contrib/gdevdj9.c-cdj970_put_params CVE-2020-16291
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vplist_635, Variable vmastergamma_640, Variable vcode_648, Literal target_0) {
		target_0.getValue()="0.1000000015"
		and not target_0.getValue()="0.1000000000000000056"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_float")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="MasterGamma"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmastergamma_640
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="9.0"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_1(Variable vcode_648, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand() instanceof AssignExpr
		and target_1.getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_1.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_648
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1))
}

predicate func_2(Variable vcode_648, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand() instanceof AssignExpr
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_648
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_2))
}

predicate func_3(Variable vcode_648, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand() instanceof AssignExpr
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_648
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_3))
}

predicate func_4(Variable vcode_648, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand() instanceof AssignExpr
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_648
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_4))
}

predicate func_5(Parameter vplist_635, Variable vmastergamma_640, Variable vcode_648, ExprStmt target_28, ExprStmt target_30, ExprStmt target_35, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_648
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_float")
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="MasterGamma"
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmastergamma_640
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0.1000000000000000056"
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="9.0"
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_5.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_648
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_5)
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_35.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_6(Variable vcode_648, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(RelationalOperation).getLesserOperand() instanceof AssignExpr
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_6.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_648
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_6))
}

predicate func_7(Variable vcode_648, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(RelationalOperation).getLesserOperand() instanceof AssignExpr
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_7.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_648
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_7))
}

predicate func_8(Variable vcode_648, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(RelationalOperation).getLesserOperand() instanceof AssignExpr
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_8.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_648
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_8))
}

predicate func_9(Variable vcode_648, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(RelationalOperation).getLesserOperand() instanceof AssignExpr
		and target_9.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_9.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_648
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_9))
}

predicate func_10(ReturnStmt target_36, Function func) {
	exists(RelationalOperation target_10 |
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand() instanceof AssignExpr
		and target_10.getGreaterOperand().(Literal).getValue()="0"
		and target_10.getParent().(IfStmt).getThen()=target_36
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Parameter vpdev_635, Variable vquality_637, AddressOfExpr target_37, ExprStmt target_19, Function func) {
	exists(IfStmt target_11 |
		target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="quality"
		and target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_635
		and target_11.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vquality_637
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="is_open"
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_635
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gs_closedevice")
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_635
		and target_11.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_11)
		and target_37.getOperand().(VariableAccess).getLocation().isBefore(target_11.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_11.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_12(Parameter vpdev_635) {
	exists(FunctionCall target_12 |
		target_12.getTarget().hasName("gs_closedevice")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vpdev_635)
}

*/
predicate func_14(Variable vcode_648, ReturnStmt target_36, RelationalOperation target_14) {
		 (target_14 instanceof GTExpr or target_14 instanceof LTExpr)
		and target_14.getLesserOperand().(VariableAccess).getTarget()=vcode_648
		and target_14.getGreaterOperand().(Literal).getValue()="0"
		and target_14.getParent().(IfStmt).getThen()=target_36
}

predicate func_15(Parameter vplist_635, Variable vbpp_647, Variable vcode_648, AssignExpr target_15) {
		target_15.getLValue().(VariableAccess).getTarget()=vcode_648
		and target_15.getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_int")
		and target_15.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_15.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="BitsPerPixel"
		and target_15.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbpp_647
		and target_15.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_15.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="32"
		and target_15.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_16(Parameter vplist_635, Variable vquality_637, Variable vcode_648, AssignExpr target_16) {
		target_16.getLValue().(VariableAccess).getTarget()=vcode_648
		and target_16.getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_int")
		and target_16.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_16.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Quality"
		and target_16.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vquality_637
		and target_16.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_16.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_16.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_17(Parameter vplist_635, Variable vpapertype_638, Variable vcode_648, AssignExpr target_17) {
		target_17.getLValue().(VariableAccess).getTarget()=vcode_648
		and target_17.getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_int")
		and target_17.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_17.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Papertype"
		and target_17.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpapertype_638
		and target_17.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_17.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="4"
		and target_17.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_18(Parameter vplist_635, Variable vduplex_639, Variable vcode_648, AssignExpr target_18) {
		target_18.getLValue().(VariableAccess).getTarget()=vcode_648
		and target_18.getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_int")
		and target_18.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_18.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Duplex"
		and target_18.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vduplex_639
		and target_18.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_18.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_18.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_19(Parameter vpdev_635, Variable vquality_637, Function func, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="quality"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_635
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vquality_637
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19
}

predicate func_20(Parameter vplist_635, Variable vgammavalc_641, Variable vcode_648, AssignExpr target_20) {
		target_20.getLValue().(VariableAccess).getTarget()=vcode_648
		and target_20.getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_float")
		and target_20.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_20.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="GammaValC"
		and target_20.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgammavalc_641
		and target_20.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0.0"
		and target_20.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="9.0"
		and target_20.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_21(Parameter vplist_635, Variable vgammavalm_642, Variable vcode_648, AssignExpr target_21) {
		target_21.getLValue().(VariableAccess).getTarget()=vcode_648
		and target_21.getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_float")
		and target_21.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_21.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="GammaValM"
		and target_21.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgammavalm_642
		and target_21.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0.0"
		and target_21.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="9.0"
		and target_21.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_22(Parameter vplist_635, Variable vgammavaly_643, Variable vcode_648, AssignExpr target_22) {
		target_22.getLValue().(VariableAccess).getTarget()=vcode_648
		and target_22.getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_float")
		and target_22.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_22.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="GammaValY"
		and target_22.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgammavaly_643
		and target_22.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0.0"
		and target_22.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="9.0"
		and target_22.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_23(Parameter vplist_635, Variable vgammavalk_644, Variable vcode_648, AssignExpr target_23) {
		target_23.getLValue().(VariableAccess).getTarget()=vcode_648
		and target_23.getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_float")
		and target_23.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_23.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="GammaValK"
		and target_23.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgammavalk_644
		and target_23.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0.0"
		and target_23.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="9.0"
		and target_23.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_24(Parameter vplist_635, Variable vblackcorrect_645, Variable vcode_648, AssignExpr target_24) {
		target_24.getLValue().(VariableAccess).getTarget()=vcode_648
		and target_24.getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_float")
		and target_24.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_24.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="BlackCorrect"
		and target_24.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vblackcorrect_645
		and target_24.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0.0"
		and target_24.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="9.0"
		and target_24.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
}

predicate func_26(Function func, ExprStmt target_26) {
		target_26.getExpr() instanceof AssignExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_26
}

predicate func_27(Function func, ExprStmt target_27) {
		target_27.getExpr() instanceof AssignExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_27
}

predicate func_28(Function func, ExprStmt target_28) {
		target_28.getExpr() instanceof AssignExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_28
}

predicate func_29(Parameter vplist_635, Variable vmastergamma_640, Variable vcode_648, Function func, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_648
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdj_put_param_float")
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vplist_635
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="MasterGamma"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmastergamma_640
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3) instanceof Literal
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="9.0"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcode_648
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_29
}

predicate func_30(Function func, ExprStmt target_30) {
		target_30.getExpr() instanceof AssignExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_30
}

predicate func_31(Function func, ExprStmt target_31) {
		target_31.getExpr() instanceof AssignExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_31
}

predicate func_32(Function func, ExprStmt target_32) {
		target_32.getExpr() instanceof AssignExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_32
}

predicate func_33(Function func, ExprStmt target_33) {
		target_33.getExpr() instanceof AssignExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_33
}

predicate func_34(Function func, ExprStmt target_34) {
		target_34.getExpr() instanceof AssignExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_34
}

predicate func_35(Parameter vpdev_635, Variable vmastergamma_640, ExprStmt target_35) {
		target_35.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mastergamma"
		and target_35.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_635
		and target_35.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vmastergamma_640
}

predicate func_36(Variable vcode_648, ReturnStmt target_36) {
		target_36.getExpr().(VariableAccess).getTarget()=vcode_648
}

predicate func_37(Variable vquality_637, AddressOfExpr target_37) {
		target_37.getOperand().(VariableAccess).getTarget()=vquality_637
}

from Function func, Parameter vpdev_635, Parameter vplist_635, Variable vquality_637, Variable vpapertype_638, Variable vduplex_639, Variable vmastergamma_640, Variable vgammavalc_641, Variable vgammavalm_642, Variable vgammavaly_643, Variable vgammavalk_644, Variable vblackcorrect_645, Variable vbpp_647, Variable vcode_648, Literal target_0, RelationalOperation target_14, AssignExpr target_15, AssignExpr target_16, AssignExpr target_17, AssignExpr target_18, ExprStmt target_19, AssignExpr target_20, AssignExpr target_21, AssignExpr target_22, AssignExpr target_23, AssignExpr target_24, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, ExprStmt target_30, ExprStmt target_31, ExprStmt target_32, ExprStmt target_33, ExprStmt target_34, ExprStmt target_35, ReturnStmt target_36, AddressOfExpr target_37
where
func_0(vplist_635, vmastergamma_640, vcode_648, target_0)
and not func_1(vcode_648, func)
and not func_2(vcode_648, func)
and not func_3(vcode_648, func)
and not func_4(vcode_648, func)
and not func_5(vplist_635, vmastergamma_640, vcode_648, target_28, target_30, target_35, func)
and not func_6(vcode_648, func)
and not func_7(vcode_648, func)
and not func_8(vcode_648, func)
and not func_9(vcode_648, func)
and not func_10(target_36, func)
and not func_11(vpdev_635, vquality_637, target_37, target_19, func)
and func_14(vcode_648, target_36, target_14)
and func_15(vplist_635, vbpp_647, vcode_648, target_15)
and func_16(vplist_635, vquality_637, vcode_648, target_16)
and func_17(vplist_635, vpapertype_638, vcode_648, target_17)
and func_18(vplist_635, vduplex_639, vcode_648, target_18)
and func_19(vpdev_635, vquality_637, func, target_19)
and func_20(vplist_635, vgammavalc_641, vcode_648, target_20)
and func_21(vplist_635, vgammavalm_642, vcode_648, target_21)
and func_22(vplist_635, vgammavaly_643, vcode_648, target_22)
and func_23(vplist_635, vgammavalk_644, vcode_648, target_23)
and func_24(vplist_635, vblackcorrect_645, vcode_648, target_24)
and func_26(func, target_26)
and func_27(func, target_27)
and func_28(func, target_28)
and func_29(vplist_635, vmastergamma_640, vcode_648, func, target_29)
and func_30(func, target_30)
and func_31(func, target_31)
and func_32(func, target_32)
and func_33(func, target_33)
and func_34(func, target_34)
and func_35(vpdev_635, vmastergamma_640, target_35)
and func_36(vcode_648, target_36)
and func_37(vquality_637, target_37)
and vpdev_635.getType().hasName("gx_device *")
and vplist_635.getType().hasName("gs_param_list *")
and vquality_637.getType().hasName("int")
and vpapertype_638.getType().hasName("int")
and vduplex_639.getType().hasName("int")
and vmastergamma_640.getType().hasName("float")
and vgammavalc_641.getType().hasName("float")
and vgammavalm_642.getType().hasName("float")
and vgammavaly_643.getType().hasName("float")
and vgammavalk_644.getType().hasName("float")
and vblackcorrect_645.getType().hasName("float")
and vbpp_647.getType().hasName("int")
and vcode_648.getType().hasName("int")
and vpdev_635.getFunction() = func
and vplist_635.getFunction() = func
and vquality_637.(LocalVariable).getFunction() = func
and vpapertype_638.(LocalVariable).getFunction() = func
and vduplex_639.(LocalVariable).getFunction() = func
and vmastergamma_640.(LocalVariable).getFunction() = func
and vgammavalc_641.(LocalVariable).getFunction() = func
and vgammavalm_642.(LocalVariable).getFunction() = func
and vgammavaly_643.(LocalVariable).getFunction() = func
and vgammavalk_644.(LocalVariable).getFunction() = func
and vblackcorrect_645.(LocalVariable).getFunction() = func
and vbpp_647.(LocalVariable).getFunction() = func
and vcode_648.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
