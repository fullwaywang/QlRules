/**
 * @name imagemagick-6b6bff054d569a77973f2140c0e86366e6168a6c-ReadCALSImage
 * @id cpp/imagemagick/6b6bff054d569a77973f2140c0e86366e6168a6c/ReadCALSImage
 * @description imagemagick-6b6bff054d569a77973f2140c0e86366e6168a6c-coders/cals.c-ReadCALSImage CVE-2018-16643
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_161, EqualityOperation target_3, ExprStmt target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_161
		and target_0.getThen().(BreakStmt).toString() = "break;"
		and target_0.getParent().(WhileStmt).getCondition()=target_3)
}

predicate func_1(Variable vfile_152, Variable vc_161, FunctionCall target_1) {
		target_1.getTarget().hasName("fputc")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vc_161
		and target_1.getArgument(1).(VariableAccess).getTarget()=vfile_152
}

predicate func_2(EqualityOperation target_3, Function func, ExprStmt target_2) {
		target_2.getExpr() instanceof FunctionCall
		and target_2.getParent().(WhileStmt).getCondition()=target_3
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vc_161, EqualityOperation target_3) {
		target_3.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_161
		and target_3.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadBlobByte")
		and target_3.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

from Function func, Variable vfile_152, Variable vc_161, FunctionCall target_1, ExprStmt target_2, EqualityOperation target_3
where
not func_0(vc_161, target_3, target_2)
and func_1(vfile_152, vc_161, target_1)
and func_2(target_3, func, target_2)
and func_3(vc_161, target_3)
and vfile_152.getType().hasName("FILE *")
and vc_161.getType().hasName("int")
and vfile_152.getParentScope+() = func
and vc_161.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
