/**
 * @name imagemagick-35893e7cad78ce461fcaffa56076c11700ba5e4e-RegisterStaticModules
 * @id cpp/imagemagick/35893e7cad78ce461fcaffa56076c11700ba5e4e/RegisterStaticModules
 * @description imagemagick-35893e7cad78ce461fcaffa56076c11700ba5e4e-MagickCore/static.c-RegisterStaticModules CVE-2021-39212
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_290, Variable vMagickModules, EqualityOperation target_2, ArrayExpr target_3, ArrayExpr target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("IsRightsAuthorized")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="module"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vMagickModules
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_290
		and target_0.getThen().(ContinueStmt).toString() = "continue;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_4.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(LabelStmt target_1 |
		target_1.toString() = "label ...:"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vi_290, Variable vMagickModules, EqualityOperation target_2) {
		target_2.getAnOperand().(ValueFieldAccess).getTarget().getName()="registered"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vMagickModules
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_290
}

predicate func_3(Variable vi_290, Variable vMagickModules, ArrayExpr target_3) {
		target_3.getArrayBase().(VariableAccess).getTarget()=vMagickModules
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vi_290
}

predicate func_4(Variable vi_290, Variable vMagickModules, ArrayExpr target_4) {
		target_4.getArrayBase().(VariableAccess).getTarget()=vMagickModules
		and target_4.getArrayOffset().(VariableAccess).getTarget()=vi_290
}

from Function func, Variable vi_290, Variable vMagickModules, EqualityOperation target_2, ArrayExpr target_3, ArrayExpr target_4
where
not func_0(vi_290, vMagickModules, target_2, target_3, target_4)
and not func_1(func)
and func_2(vi_290, vMagickModules, target_2)
and func_3(vi_290, vMagickModules, target_3)
and func_4(vi_290, vMagickModules, target_4)
and vi_290.getType().hasName("ssize_t")
and vMagickModules.getType() instanceof ArrayType
and vi_290.getParentScope+() = func
and not vMagickModules.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
