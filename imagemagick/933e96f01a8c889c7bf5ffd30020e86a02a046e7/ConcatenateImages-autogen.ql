/**
 * @name imagemagick-933e96f01a8c889c7bf5ffd30020e86a02a046e7-ConcatenateImages
 * @id cpp/imagemagick/933e96f01a8c889c7bf5ffd30020e86a02a046e7/ConcatenateImages
 * @description imagemagick-933e96f01a8c889c7bf5ffd30020e86a02a046e7-MagickWand/magick-cli.c-ConcatenateImages CVE-2016-10060
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("MagickBooleanType")
		and target_0.getRValue() instanceof EnumConstantAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vc_646, AssignExpr target_5) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_646
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("MagickBooleanType")
		and target_5.getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable voutput_643, Variable vc_646, FunctionCall target_3) {
		target_3.getTarget().hasName("fputc")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vc_646
		and target_3.getArgument(1).(VariableAccess).getTarget()=voutput_643
}

predicate func_5(Variable vc_646, AssignExpr target_5) {
		target_5.getLValue().(VariableAccess).getTarget()=vc_646
		and target_5.getRValue().(FunctionCall).getTarget().hasName("fgetc")
}

from Function func, Variable voutput_643, Variable vc_646, FunctionCall target_3, AssignExpr target_5
where
not func_0(func)
and not func_1(vc_646, target_5)
and func_3(voutput_643, vc_646, target_3)
and func_5(vc_646, target_5)
and voutput_643.getType().hasName("FILE *")
and vc_646.getType().hasName("int")
and voutput_643.getParentScope+() = func
and vc_646.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
