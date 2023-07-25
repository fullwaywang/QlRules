/**
 * @name openjpeg-784d4d47e97b5d0fccccbd931349997a0e2074cc-imagetopnm
 * @id cpp/openjpeg/784d4d47e97b5d0fccccbd931349997a0e2074cc/imagetopnm
 * @description openjpeg-784d4d47e97b5d0fccccbd931349997a0e2074cc-src/bin/jp2/convert.c-imagetopnm CVE-2016-9114
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1925"
		and not target_0.getValue()="1926"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s:%d:imagetopnm\n\tprecision %d is larger than 16\n\t: refused.\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="/opt/project/build/cloned/openjpeg/src/bin/jp2/convert.c"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vncomp_1913, BlockStmt target_3, ExprStmt target_4, ExprStmt target_5) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vncomp_1913
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("are_comps_similar")
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_3
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vforce_split_1908, BlockStmt target_3, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vforce_split_1908
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("are_comps_similar")
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fopen")
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="wb"
		and target_3.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_3.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ERROR -> failed to open %s for writing\n"
		and target_3.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
}

predicate func_4(Variable vncomp_1913, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vncomp_1913
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_5(Variable vncomp_1913, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vncomp_1913
		and target_5.getExpr().(AssignExpr).getRValue().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
}

from Function func, Parameter vforce_split_1908, Variable vncomp_1913, Literal target_0, EqualityOperation target_2, BlockStmt target_3, ExprStmt target_4, ExprStmt target_5
where
func_0(func, target_0)
and not func_1(vncomp_1913, target_3, target_4, target_5)
and func_2(vforce_split_1908, target_3, target_2)
and func_3(target_3)
and func_4(vncomp_1913, target_4)
and func_5(vncomp_1913, target_5)
and vforce_split_1908.getType().hasName("int")
and vncomp_1913.getType().hasName("unsigned int")
and vforce_split_1908.getParentScope+() = func
and vncomp_1913.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
