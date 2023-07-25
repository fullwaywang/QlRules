/**
 * @name imagemagick-716496e6df0add89e9679d6da9c0afca814cfe49-CLINoImageOperator
 * @id cpp/imagemagick/716496e6df0add89e9679d6da9c0afca814cfe49/CLINoImageOperator
 * @description imagemagick-716496e6df0add89e9679d6da9c0afca814cfe49-MagickWand/operation.c-CLINoImageOperator CVE-2022-2719
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwrite_images_4910, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vwrite_images_4910
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable varg1_4788, Variable vwrite_images_4910, Variable vwrite_info_4913, Parameter vcli_wand_4784, EqualityOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("WriteImages")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwrite_info_4913
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vwrite_images_4910
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=varg1_4788
		and target_1.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="exception"
		and target_1.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="wand"
		and target_1.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcli_wand_4784
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("LocaleCompare")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="write"
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vwrite_images_4910, Parameter vcli_wand_4784, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwrite_images_4910
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CloneImageList")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="images"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="wand"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcli_wand_4784
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="exception"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="wand"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcli_wand_4784
}

from Function func, Variable varg1_4788, Variable vwrite_images_4910, Variable vwrite_info_4913, Parameter vcli_wand_4784, ExprStmt target_1, EqualityOperation target_2, ExprStmt target_3
where
not func_0(vwrite_images_4910, target_2, target_3, target_1)
and func_1(varg1_4788, vwrite_images_4910, vwrite_info_4913, vcli_wand_4784, target_2, target_1)
and func_2(target_2)
and func_3(vwrite_images_4910, vcli_wand_4784, target_3)
and varg1_4788.getType().hasName("const char *")
and vwrite_images_4910.getType().hasName("Image *")
and vwrite_info_4913.getType().hasName("ImageInfo *")
and vcli_wand_4784.getType().hasName("MagickCLI *")
and varg1_4788.getParentScope+() = func
and vwrite_images_4910.getParentScope+() = func
and vwrite_info_4913.getParentScope+() = func
and vcli_wand_4784.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
