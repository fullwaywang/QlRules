/**
 * @name ffmpeg-ad3b6fa7d83db7de951ed891649af93a47e74be5-bayer_to_rgb24_wrapper
 * @id cpp/ffmpeg/ad3b6fa7d83db7de951ed891649af93a47e74be5/bayer-to-rgb24-wrapper
 * @description ffmpeg-ad3b6fa7d83db7de951ed891649af93a47e74be5-libswscale/swscale_unscaled.c-bayer_to_rgb24_wrapper CVE-2016-2328
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsrcSliceH_1033, RelationalOperation target_5, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsrcSliceH_1033
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="srcSliceH > 1"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vc_1032, Parameter vsrcStride_1032, Parameter vsrcSliceH_1033, Parameter vdstStride_1033, Variable vdstPtr_1035, Variable vsrcPtr_1036, Variable vi_1037, Variable vcopy_1038, ExprStmt target_6, ArrayExpr target_7, RelationalOperation target_5, ReturnStmt target_8, ExprStmt target_9, ArrayExpr target_10, ExprStmt target_4, AssignAddExpr target_11, ExprStmt target_12, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_1037
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsrcSliceH_1033
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vcopy_1038
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsrcPtr_1036
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1032
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdstPtr_1035
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1033
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="srcW"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1032
		and target_1.getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1037
		and target_1.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsrcSliceH_1033
		and target_1.getElse().(IfStmt).getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1)
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_7.getArrayBase().(VariableAccess).getLocation())
		and target_5.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_10.getArrayBase().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_4.getExpr().(VariableCall).getArgument(2).(VariableAccess).getLocation())
		and target_11.getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_12.getExpr().(VariableCall).getExpr().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vc_1032, Parameter vsrcStride_1032, Parameter vdstStride_1033, Variable vdstPtr_1035, Variable vsrcPtr_1036, Variable vcopy_1038, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="srcW"
		and target_3.getQualifier().(VariableAccess).getTarget()=vc_1032
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vcopy_1038
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsrcPtr_1036
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1032
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdstPtr_1035
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1033
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
predicate func_4(Parameter vc_1032, Parameter vsrcStride_1032, Parameter vdstStride_1033, Variable vdstPtr_1035, Variable vsrcPtr_1036, Variable vcopy_1038, Function func, ExprStmt target_4) {
		target_4.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vcopy_1038
		and target_4.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsrcPtr_1036
		and target_4.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1032
		and target_4.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdstPtr_1035
		and target_4.getExpr().(VariableCall).getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1033
		and target_4.getExpr().(VariableCall).getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getExpr().(VariableCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="srcW"
		and target_4.getExpr().(VariableCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1032
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vsrcSliceH_1033, Variable vi_1037, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vi_1037
		and target_5.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vsrcSliceH_1033
		and target_5.getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_6(Parameter vsrcStride_1032, Variable vsrcPtr_1036, ExprStmt target_6) {
		target_6.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vsrcPtr_1036
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1032
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_7(Parameter vsrcStride_1032, ArrayExpr target_7) {
		target_7.getArrayBase().(VariableAccess).getTarget()=vsrcStride_1032
		and target_7.getArrayOffset().(Literal).getValue()="0"
}

predicate func_8(Parameter vsrcSliceH_1033, ReturnStmt target_8) {
		target_8.getExpr().(VariableAccess).getTarget()=vsrcSliceH_1033
}

predicate func_9(Parameter vdstStride_1033, Variable vdstPtr_1035, ExprStmt target_9) {
		target_9.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdstPtr_1035
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1033
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_10(Parameter vdstStride_1033, ArrayExpr target_10) {
		target_10.getArrayBase().(VariableAccess).getTarget()=vdstStride_1033
		and target_10.getArrayOffset().(Literal).getValue()="0"
}

predicate func_11(Variable vi_1037, AssignAddExpr target_11) {
		target_11.getLValue().(VariableAccess).getTarget()=vi_1037
		and target_11.getRValue().(Literal).getValue()="2"
}

predicate func_12(Parameter vc_1032, Parameter vsrcStride_1032, Parameter vdstStride_1033, Variable vdstPtr_1035, Variable vsrcPtr_1036, Variable vcopy_1038, ExprStmt target_12) {
		target_12.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vcopy_1038
		and target_12.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsrcPtr_1036
		and target_12.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrcStride_1032
		and target_12.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdstPtr_1035
		and target_12.getExpr().(VariableCall).getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdstStride_1033
		and target_12.getExpr().(VariableCall).getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getExpr().(VariableCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="srcW"
		and target_12.getExpr().(VariableCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1032
}

from Function func, Parameter vc_1032, Parameter vsrcStride_1032, Parameter vsrcSliceH_1033, Parameter vdstStride_1033, Variable vdstPtr_1035, Variable vsrcPtr_1036, Variable vi_1037, Variable vcopy_1038, ExprStmt target_4, RelationalOperation target_5, ExprStmt target_6, ArrayExpr target_7, ReturnStmt target_8, ExprStmt target_9, ArrayExpr target_10, AssignAddExpr target_11, ExprStmt target_12
where
not func_0(vsrcSliceH_1033, target_5, func)
and not func_1(vc_1032, vsrcStride_1032, vsrcSliceH_1033, vdstStride_1033, vdstPtr_1035, vsrcPtr_1036, vi_1037, vcopy_1038, target_6, target_7, target_5, target_8, target_9, target_10, target_4, target_11, target_12, func)
and func_4(vc_1032, vsrcStride_1032, vdstStride_1033, vdstPtr_1035, vsrcPtr_1036, vcopy_1038, func, target_4)
and func_5(vsrcSliceH_1033, vi_1037, target_5)
and func_6(vsrcStride_1032, vsrcPtr_1036, target_6)
and func_7(vsrcStride_1032, target_7)
and func_8(vsrcSliceH_1033, target_8)
and func_9(vdstStride_1033, vdstPtr_1035, target_9)
and func_10(vdstStride_1033, target_10)
and func_11(vi_1037, target_11)
and func_12(vc_1032, vsrcStride_1032, vdstStride_1033, vdstPtr_1035, vsrcPtr_1036, vcopy_1038, target_12)
and vc_1032.getType().hasName("SwsContext *")
and vsrcStride_1032.getType().hasName("int[]")
and vsrcSliceH_1033.getType().hasName("int")
and vdstStride_1033.getType().hasName("int[]")
and vdstPtr_1035.getType().hasName("uint8_t *")
and vsrcPtr_1036.getType().hasName("const uint8_t *")
and vi_1037.getType().hasName("int")
and vcopy_1038.getType().hasName("..(*)(..)")
and vc_1032.getParentScope+() = func
and vsrcStride_1032.getParentScope+() = func
and vsrcSliceH_1033.getParentScope+() = func
and vdstStride_1033.getParentScope+() = func
and vdstPtr_1035.getParentScope+() = func
and vsrcPtr_1036.getParentScope+() = func
and vi_1037.getParentScope+() = func
and vcopy_1038.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
