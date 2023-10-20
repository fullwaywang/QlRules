/**
 * @name imagemagick-70aa86f5d5d8aa605a918ed51f7574f433a18482-sRGBTransformImage
 * @id cpp/imagemagick/70aa86f5d5d8aa605a918ed51f7574f433a18482/sRGBTransformImage
 * @description imagemagick-70aa86f5d5d8aa605a918ed51f7574f433a18482-MagickCore/colorspace.c-sRGBTransformImage CVE-2021-20311
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfilm_gamma_910, ExprStmt target_8) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand() instanceof MulExpr
		and target_0.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfilm_gamma_910
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pow")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="10.0"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof DivExpr
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vfilm_gamma_910, DivExpr target_6) {
	exists(MulExpr target_1 |
		target_1.getLeftOperand() instanceof MulExpr
		and target_1.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfilm_gamma_910
		and target_6.getRightOperand().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vdensity_909, Variable vgamma_911, Variable vreference_black_912, Variable vreference_white_913, MulExpr target_2) {
		target_2.getLeftOperand().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vreference_black_912
		and target_2.getLeftOperand().(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vreference_white_913
		and target_2.getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vgamma_911
		and target_2.getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vdensity_909
		and target_2.getRightOperand().(Literal).getValue()="0.002000000000000000042"
}

predicate func_3(Variable vdensity_909, Variable vgamma_911, MulExpr target_3) {
		target_3.getLeftOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vgamma_911
		and target_3.getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vdensity_909
		and target_3.getRightOperand().(Literal).getValue()="0.002000000000000000042"
}

predicate func_4(Variable vfilm_gamma_910, VariableAccess target_4) {
		target_4.getTarget()=vfilm_gamma_910
}

predicate func_5(Variable vfilm_gamma_910, VariableAccess target_5) {
		target_5.getTarget()=vfilm_gamma_910
}

predicate func_6(Variable vfilm_gamma_910, DivExpr target_6) {
		target_6.getLeftOperand() instanceof MulExpr
		and target_6.getRightOperand().(VariableAccess).getTarget()=vfilm_gamma_910
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pow")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="10.0"
}

predicate func_7(Variable vfilm_gamma_910, DivExpr target_7) {
		target_7.getLeftOperand() instanceof MulExpr
		and target_7.getRightOperand().(VariableAccess).getTarget()=vfilm_gamma_910
}

predicate func_8(Variable vfilm_gamma_910, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfilm_gamma_910
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("StringToDouble")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

from Function func, Variable vdensity_909, Variable vfilm_gamma_910, Variable vgamma_911, Variable vreference_black_912, Variable vreference_white_913, MulExpr target_2, MulExpr target_3, VariableAccess target_4, VariableAccess target_5, DivExpr target_6, DivExpr target_7, ExprStmt target_8
where
not func_0(vfilm_gamma_910, target_8)
and not func_1(vfilm_gamma_910, target_6)
and func_2(vdensity_909, vgamma_911, vreference_black_912, vreference_white_913, target_2)
and func_3(vdensity_909, vgamma_911, target_3)
and func_4(vfilm_gamma_910, target_4)
and func_5(vfilm_gamma_910, target_5)
and func_6(vfilm_gamma_910, target_6)
and func_7(vfilm_gamma_910, target_7)
and func_8(vfilm_gamma_910, target_8)
and vdensity_909.getType().hasName("double")
and vfilm_gamma_910.getType().hasName("double")
and vgamma_911.getType().hasName("double")
and vreference_black_912.getType().hasName("double")
and vreference_white_913.getType().hasName("double")
and vdensity_909.getParentScope+() = func
and vfilm_gamma_910.getParentScope+() = func
and vgamma_911.getParentScope+() = func
and vreference_black_912.getParentScope+() = func
and vreference_white_913.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
