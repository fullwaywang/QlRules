/**
 * @name imagemagick-329dd528ab79531d884c0ba131e97d43f872ab5d-ImplodeImage
 * @id cpp/imagemagick/329dd528ab79531d884c0ba131e97d43f872ab5d/ImplodeImage
 * @description imagemagick-329dd528ab79531d884c0ba131e97d43f872ab5d-MagickCore/visual-effects.c-ImplodeImage CVE-2021-20244
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcanvas_image_956, Variable vscale_967) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
		and target_0.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rows"
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="y"
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscale_967)
}

predicate func_1(Variable vcanvas_image_956, Variable vscale_967, RelationalOperation target_21) {
	exists(MulExpr target_1 |
		target_1.getLeftOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
		and target_1.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="x"
		and target_1.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscale_967
		and target_21.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vradius_953, RelationalOperation target_23) {
	exists(MulExpr target_2 |
		target_2.getLeftOperand() instanceof MulExpr
		and target_2.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_2.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vradius_953
		and target_23.getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Function func) {
	exists(MulExpr target_3 |
		target_3.getLeftOperand() instanceof MulExpr
		and target_3.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_3.getRightOperand().(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(MulExpr target_4 |
		target_4.getLeftOperand() instanceof MulExpr
		and target_4.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_4.getRightOperand().(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vcanvas_image_956, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="columns"
		and target_5.getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
}

predicate func_6(Variable vcanvas_image_956, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="rows"
		and target_6.getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
}

predicate func_7(Variable vcanvas_image_956, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="rows"
		and target_7.getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
}

predicate func_8(Variable vcanvas_image_956, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="columns"
		and target_8.getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
}

predicate func_9(Variable vdistance_1030, MulExpr target_9) {
		target_9.getLeftOperand().(Literal).getValue()="3.141592653589793116"
		and target_9.getRightOperand().(FunctionCall).getTarget().hasName("sqrt")
		and target_9.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdistance_1030
}

predicate func_10(Variable vfactor_1081, Variable vdelta_1033, MulExpr target_10) {
		target_10.getLeftOperand().(VariableAccess).getTarget()=vfactor_1081
		and target_10.getRightOperand().(ValueFieldAccess).getTarget().getName()="x"
		and target_10.getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdelta_1033
}

predicate func_11(Variable vscale_967, ValueFieldAccess target_11) {
		target_11.getTarget().getName()="x"
		and target_11.getQualifier().(VariableAccess).getTarget()=vscale_967
}

predicate func_12(Variable vfactor_1081, Variable vdelta_1033, MulExpr target_12) {
		target_12.getLeftOperand().(VariableAccess).getTarget()=vfactor_1081
		and target_12.getRightOperand().(ValueFieldAccess).getTarget().getName()="y"
		and target_12.getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdelta_1033
}

predicate func_13(Variable vscale_967, ValueFieldAccess target_13) {
		target_13.getTarget().getName()="y"
		and target_13.getQualifier().(VariableAccess).getTarget()=vscale_967
}

predicate func_14(Variable vradius_953, VariableAccess target_14) {
		target_14.getTarget()=vradius_953
}

predicate func_15(Variable vcanvas_image_956, Variable vscale_967, DivExpr target_15) {
		target_15.getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_15.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
		and target_15.getRightOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_15.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
		and target_15.getParent().(AssignExpr).getRValue() = target_15
		and target_15.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="y"
		and target_15.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscale_967
}

predicate func_16(Variable vcanvas_image_956, Variable vscale_967, DivExpr target_16) {
		target_16.getLeftOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_16.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
		and target_16.getRightOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_16.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
		and target_16.getParent().(AssignExpr).getRValue() = target_16
		and target_16.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="x"
		and target_16.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscale_967
}

predicate func_17(Variable vradius_953, DivExpr target_17) {
		target_17.getLeftOperand() instanceof MulExpr
		and target_17.getRightOperand().(VariableAccess).getTarget()=vradius_953
}

predicate func_18(Function func, DivExpr target_18) {
		target_18.getLeftOperand() instanceof MulExpr
		and target_18.getRightOperand() instanceof ValueFieldAccess
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Function func, DivExpr target_19) {
		target_19.getLeftOperand() instanceof MulExpr
		and target_19.getRightOperand() instanceof ValueFieldAccess
		and target_19.getEnclosingFunction() = func
}

predicate func_21(Variable vcanvas_image_956, RelationalOperation target_21) {
		 (target_21 instanceof GTExpr or target_21 instanceof LTExpr)
		and target_21.getLesserOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_21.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
		and target_21.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_21.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcanvas_image_956
}

predicate func_23(Variable vradius_953, Variable vdistance_1030, RelationalOperation target_23) {
		 (target_23 instanceof GEExpr or target_23 instanceof LEExpr)
		and target_23.getGreaterOperand().(VariableAccess).getTarget()=vdistance_1030
		and target_23.getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vradius_953
		and target_23.getLesserOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vradius_953
}

from Function func, Variable vfactor_1081, Variable vradius_953, Variable vcanvas_image_956, Variable vscale_967, Variable vdistance_1030, Variable vdelta_1033, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, PointerFieldAccess target_8, MulExpr target_9, MulExpr target_10, ValueFieldAccess target_11, MulExpr target_12, ValueFieldAccess target_13, VariableAccess target_14, DivExpr target_15, DivExpr target_16, DivExpr target_17, DivExpr target_18, DivExpr target_19, RelationalOperation target_21, RelationalOperation target_23
where
not func_0(vcanvas_image_956, vscale_967)
and not func_1(vcanvas_image_956, vscale_967, target_21)
and not func_2(vradius_953, target_23)
and not func_3(func)
and not func_4(func)
and func_5(vcanvas_image_956, target_5)
and func_6(vcanvas_image_956, target_6)
and func_7(vcanvas_image_956, target_7)
and func_8(vcanvas_image_956, target_8)
and func_9(vdistance_1030, target_9)
and func_10(vfactor_1081, vdelta_1033, target_10)
and func_11(vscale_967, target_11)
and func_12(vfactor_1081, vdelta_1033, target_12)
and func_13(vscale_967, target_13)
and func_14(vradius_953, target_14)
and func_15(vcanvas_image_956, vscale_967, target_15)
and func_16(vcanvas_image_956, vscale_967, target_16)
and func_17(vradius_953, target_17)
and func_18(func, target_18)
and func_19(func, target_19)
and func_21(vcanvas_image_956, target_21)
and func_23(vradius_953, vdistance_1030, target_23)
and vfactor_1081.getType().hasName("double")
and vradius_953.getType().hasName("double")
and vcanvas_image_956.getType().hasName("Image *")
and vscale_967.getType().hasName("PointInfo")
and vdistance_1030.getType().hasName("double")
and vdelta_1033.getType().hasName("PointInfo")
and vfactor_1081.getParentScope+() = func
and vradius_953.getParentScope+() = func
and vcanvas_image_956.getParentScope+() = func
and vscale_967.getParentScope+() = func
and vdistance_1030.getParentScope+() = func
and vdelta_1033.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
