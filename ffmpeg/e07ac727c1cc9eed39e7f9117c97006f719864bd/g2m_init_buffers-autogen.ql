/**
 * @name ffmpeg-e07ac727c1cc9eed39e7f9117c97006f719864bd-g2m_init_buffers
 * @id cpp/ffmpeg/e07ac727c1cc9eed39e7f9117c97006f719864bd/g2m-init-buffers
 * @description ffmpeg-e07ac727c1cc9eed39e7f9117c97006f719864bd-libavcodec/g2meet.c-g2m_init_buffers CVE-2013-7022
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Parameter vc_441, ExprStmt target_9, ExprStmt target_10, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="height"
		and target_0.getQualifier().(VariableAccess).getTarget()=vc_441
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_1(Parameter vc_441, Literal target_1) {
		target_1.getValue()="16"
		and not target_1.getValue()="15"
		and target_1.getParent().(AddExpr).getParent().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getParent().(AddExpr).getParent().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_441
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="1"
		and not target_2.getValue()="15"
		and target_2.getParent().(SubExpr).getParent().(BitwiseAndExpr).getLeftOperand() instanceof SubExpr
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vc_441, ExprStmt target_9, ExprStmt target_10) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_441
		and target_3.getAnOperand().(Literal).getValue()="15"
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Function func, ComplementExpr target_4) {
		target_4.getValue()="-16"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Parameter vc_441, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="width"
		and target_5.getQualifier().(VariableAccess).getTarget()=vc_441
}

/*predicate func_6(Parameter vc_441, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="height"
		and target_6.getQualifier().(VariableAccess).getTarget()=vc_441
}

*/
predicate func_7(Function func, ComplementExpr target_7) {
		target_7.getValue()="-16"
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Parameter vc_441, BitwiseAndExpr target_8) {
		target_8.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_8.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_441
		and target_8.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_8.getLeftOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_8.getRightOperand() instanceof ComplementExpr
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_9(Parameter vc_441, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="framebuf_stride"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_441
		and target_9.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_9.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_9.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_9.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_9.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand() instanceof ComplementExpr
}

predicate func_10(Parameter vc_441, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("av_free")
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="framebuf"
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_441
}

from Function func, Parameter vc_441, Literal target_1, Literal target_2, ComplementExpr target_4, PointerFieldAccess target_5, ComplementExpr target_7, BitwiseAndExpr target_8, ExprStmt target_9, ExprStmt target_10
where
func_1(vc_441, target_1)
and func_2(func, target_2)
and not func_3(vc_441, target_9, target_10)
and func_4(func, target_4)
and func_5(vc_441, target_5)
and func_7(func, target_7)
and func_8(vc_441, target_8)
and func_9(vc_441, target_9)
and func_10(vc_441, target_10)
and vc_441.getType().hasName("G2MContext *")
and vc_441.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
