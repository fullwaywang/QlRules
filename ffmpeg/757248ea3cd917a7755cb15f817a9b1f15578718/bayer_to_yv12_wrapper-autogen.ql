/**
 * @name ffmpeg-757248ea3cd917a7755cb15f817a9b1f15578718-bayer_to_yv12_wrapper
 * @id cpp/ffmpeg/757248ea3cd917a7755cb15f817a9b1f15578718/bayer-to-yv12-wrapper
 * @description ffmpeg-757248ea3cd917a7755cb15f817a9b1f15578718-libswscale/swscale_unscaled.c-bayer_to_yv12_wrapper CVE-2016-2328
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsrcSliceH_1082, RelationalOperation target_7, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsrcSliceH_1082
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="srcSliceH > 1"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vc_1081, Parameter vsrcStride_1081, Parameter vsrcSliceH_1082, Parameter vdstStride_1082, Variable vsrcPtr_1084, Variable vdstY_1085, Variable vdstU_1086, Variable vdstV_1087, Variable vi_1088, Variable vcopy_1089, ExprStmt target_8, ArrayExpr target_9, RelationalOperation target_7, ReturnStmt target_10, ExprStmt target_11, ArrayExpr target_12, ExprStmt target_6, ExprStmt target_13, ExprStmt target_14, AssignAddExpr target_15, ExprStmt target_16, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_1088
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsrcSliceH_1082
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vcopy_1089
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsrcPtr_1084
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1081
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdstY_1085
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vdstU_1086
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(4).(VariableAccess).getTarget()=vdstV_1087
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(5).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1082
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(5).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="srcW"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1081
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="input_rgb2yuv_table"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1081
		and target_1.getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1088
		and target_1.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsrcSliceH_1082
		and target_1.getElse().(IfStmt).getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_1)
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_9.getArrayBase().(VariableAccess).getLocation())
		and target_7.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(5).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(5).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_12.getArrayBase().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_13.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getLocation())
		and target_14.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getLocation())
		and target_15.getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_16.getExpr().(VariableCall).getExpr().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getLocation()))
}

/*predicate func_4(Parameter vc_1081, Parameter vsrcStride_1081, Parameter vdstStride_1082, Variable vsrcPtr_1084, Variable vdstY_1085, Variable vdstU_1086, Variable vdstV_1087, Variable vcopy_1089, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="srcW"
		and target_4.getQualifier().(VariableAccess).getTarget()=vc_1081
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vcopy_1089
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsrcPtr_1084
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1081
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdstY_1085
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vdstU_1086
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(4).(VariableAccess).getTarget()=vdstV_1087
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(5).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1082
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(5).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="input_rgb2yuv_table"
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1081
}

*/
/*predicate func_5(Parameter vc_1081, Parameter vsrcStride_1081, Parameter vdstStride_1082, Variable vsrcPtr_1084, Variable vdstY_1085, Variable vdstU_1086, Variable vdstV_1087, Variable vcopy_1089, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="input_rgb2yuv_table"
		and target_5.getQualifier().(VariableAccess).getTarget()=vc_1081
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vcopy_1089
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsrcPtr_1084
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1081
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdstY_1085
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vdstU_1086
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(4).(VariableAccess).getTarget()=vdstV_1087
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(5).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1082
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(5).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="srcW"
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1081
}

*/
predicate func_6(Parameter vc_1081, Parameter vsrcStride_1081, Parameter vdstStride_1082, Variable vsrcPtr_1084, Variable vdstY_1085, Variable vdstU_1086, Variable vdstV_1087, Variable vcopy_1089, Function func, ExprStmt target_6) {
		target_6.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vcopy_1089
		and target_6.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsrcPtr_1084
		and target_6.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1081
		and target_6.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdstY_1085
		and target_6.getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vdstU_1086
		and target_6.getExpr().(VariableCall).getArgument(4).(VariableAccess).getTarget()=vdstV_1087
		and target_6.getExpr().(VariableCall).getArgument(5).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1082
		and target_6.getExpr().(VariableCall).getArgument(5).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="srcW"
		and target_6.getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1081
		and target_6.getExpr().(VariableCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="input_rgb2yuv_table"
		and target_6.getExpr().(VariableCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1081
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vsrcSliceH_1082, Variable vi_1088, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vi_1088
		and target_7.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vsrcSliceH_1082
		and target_7.getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_8(Parameter vsrcStride_1081, Variable vsrcPtr_1084, ExprStmt target_8) {
		target_8.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vsrcPtr_1084
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1081
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_9(Parameter vsrcStride_1081, ArrayExpr target_9) {
		target_9.getArrayBase().(VariableAccess).getTarget()=vsrcStride_1081
		and target_9.getArrayOffset().(Literal).getValue()="0"
}

predicate func_10(Parameter vsrcSliceH_1082, ReturnStmt target_10) {
		target_10.getExpr().(VariableAccess).getTarget()=vsrcSliceH_1082
}

predicate func_11(Parameter vdstStride_1082, Variable vdstV_1087, ExprStmt target_11) {
		target_11.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdstV_1087
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1082
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_12(Parameter vdstStride_1082, ArrayExpr target_12) {
		target_12.getArrayBase().(VariableAccess).getTarget()=vdstStride_1082
		and target_12.getArrayOffset().(Literal).getValue()="0"
}

predicate func_13(Parameter vdstStride_1082, Variable vdstY_1085, ExprStmt target_13) {
		target_13.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdstY_1085
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1082
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_14(Parameter vdstStride_1082, Variable vdstU_1086, ExprStmt target_14) {
		target_14.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdstU_1086
		and target_14.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1082
		and target_14.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_15(Variable vi_1088, AssignAddExpr target_15) {
		target_15.getLValue().(VariableAccess).getTarget()=vi_1088
		and target_15.getRValue().(Literal).getValue()="2"
}

predicate func_16(Parameter vc_1081, Parameter vsrcStride_1081, Parameter vdstStride_1082, Variable vsrcPtr_1084, Variable vdstY_1085, Variable vdstU_1086, Variable vdstV_1087, Variable vcopy_1089, ExprStmt target_16) {
		target_16.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vcopy_1089
		and target_16.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsrcPtr_1084
		and target_16.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1081
		and target_16.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_16.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdstY_1085
		and target_16.getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vdstU_1086
		and target_16.getExpr().(VariableCall).getArgument(4).(VariableAccess).getTarget()=vdstV_1087
		and target_16.getExpr().(VariableCall).getArgument(5).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1082
		and target_16.getExpr().(VariableCall).getArgument(5).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_16.getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="srcW"
		and target_16.getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1081
		and target_16.getExpr().(VariableCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="input_rgb2yuv_table"
		and target_16.getExpr().(VariableCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1081
}

from Function func, Parameter vc_1081, Parameter vsrcStride_1081, Parameter vsrcSliceH_1082, Parameter vdstStride_1082, Variable vsrcPtr_1084, Variable vdstY_1085, Variable vdstU_1086, Variable vdstV_1087, Variable vi_1088, Variable vcopy_1089, ExprStmt target_6, RelationalOperation target_7, ExprStmt target_8, ArrayExpr target_9, ReturnStmt target_10, ExprStmt target_11, ArrayExpr target_12, ExprStmt target_13, ExprStmt target_14, AssignAddExpr target_15, ExprStmt target_16
where
not func_0(vsrcSliceH_1082, target_7, func)
and not func_1(vc_1081, vsrcStride_1081, vsrcSliceH_1082, vdstStride_1082, vsrcPtr_1084, vdstY_1085, vdstU_1086, vdstV_1087, vi_1088, vcopy_1089, target_8, target_9, target_7, target_10, target_11, target_12, target_6, target_13, target_14, target_15, target_16, func)
and func_6(vc_1081, vsrcStride_1081, vdstStride_1082, vsrcPtr_1084, vdstY_1085, vdstU_1086, vdstV_1087, vcopy_1089, func, target_6)
and func_7(vsrcSliceH_1082, vi_1088, target_7)
and func_8(vsrcStride_1081, vsrcPtr_1084, target_8)
and func_9(vsrcStride_1081, target_9)
and func_10(vsrcSliceH_1082, target_10)
and func_11(vdstStride_1082, vdstV_1087, target_11)
and func_12(vdstStride_1082, target_12)
and func_13(vdstStride_1082, vdstY_1085, target_13)
and func_14(vdstStride_1082, vdstU_1086, target_14)
and func_15(vi_1088, target_15)
and func_16(vc_1081, vsrcStride_1081, vdstStride_1082, vsrcPtr_1084, vdstY_1085, vdstU_1086, vdstV_1087, vcopy_1089, target_16)
and vc_1081.getType().hasName("SwsContext *")
and vsrcStride_1081.getType().hasName("int[]")
and vsrcSliceH_1082.getType().hasName("int")
and vdstStride_1082.getType().hasName("int[]")
and vsrcPtr_1084.getType().hasName("const uint8_t *")
and vdstY_1085.getType().hasName("uint8_t *")
and vdstU_1086.getType().hasName("uint8_t *")
and vdstV_1087.getType().hasName("uint8_t *")
and vi_1088.getType().hasName("int")
and vcopy_1089.getType().hasName("..(*)(..)")
and vc_1081.getParentScope+() = func
and vsrcStride_1081.getParentScope+() = func
and vsrcSliceH_1082.getParentScope+() = func
and vdstStride_1082.getParentScope+() = func
and vsrcPtr_1084.getParentScope+() = func
and vdstY_1085.getParentScope+() = func
and vdstU_1086.getParentScope+() = func
and vdstV_1087.getParentScope+() = func
and vi_1088.getParentScope+() = func
and vcopy_1089.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
