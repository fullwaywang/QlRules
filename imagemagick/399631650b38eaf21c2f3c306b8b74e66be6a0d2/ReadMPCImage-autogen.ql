/**
 * @name imagemagick-399631650b38eaf21c2f3c306b8b74e66be6a0d2-ReadMPCImage
 * @id cpp/imagemagick/399631650b38eaf21c2f3c306b8b74e66be6a0d2/ReadMPCImage
 * @description imagemagick-399631650b38eaf21c2f3c306b8b74e66be6a0d2-coders/mpc.c-ReadMPCImage CVE-2017-14324
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable voptions_151, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voptions_151
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyString")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_151
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_5, Function func, EmptyStmt target_1) {
		target_1.toString() = ";"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getEnclosingFunction() = func
}

predicate func_2(RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="number_meta_channels"
		and target_2.getLesserOperand().(Literal).getValue()="32"
}

predicate func_3(Variable voptions_151, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="number_meta_channels"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("StringToUnsignedLong")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_151
}

predicate func_4(Variable voptions_151, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ParseCommandOption")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voptions_151
}

predicate func_5(EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("LocaleCompare")
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="number-meta-channels"
		and target_5.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable voptions_151, EmptyStmt target_1, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4, EqualityOperation target_5
where
not func_0(voptions_151, target_2, target_3, target_4)
and func_1(target_5, func, target_1)
and func_2(target_2)
and func_3(voptions_151, target_3)
and func_4(voptions_151, target_4)
and func_5(target_5)
and voptions_151.getType().hasName("char *")
and voptions_151.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
