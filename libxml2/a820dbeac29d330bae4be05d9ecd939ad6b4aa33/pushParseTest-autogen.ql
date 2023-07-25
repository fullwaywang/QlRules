/**
 * @name libxml2-a820dbeac29d330bae4be05d9ecd939ad6b4aa33-pushParseTest
 * @id cpp/libxml2/a820dbeac29d330bae4be05d9ecd939ad6b4aa33/pushParseTest
 * @description libxml2-a820dbeac29d330bae4be05d9ecd939ad6b4aa33-runtest.c-pushParseTest CVE-2016-1839
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition() instanceof RelationalOperation
		and target_0.getStmt() instanceof BlockStmt
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vsize_1855, Variable vcur_1856, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vcur_1856
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vsize_1855
}

predicate func_2(Parameter voptions_1851, Variable vctxt_1852, Variable vsize_1855, Variable vcur_1856, RelationalOperation target_1, BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcur_1856
		and target_2.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1024"
		and target_2.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_1855
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=voptions_1851
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="16777216"
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("htmlParseChunk")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_1852
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParseChunk")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_1852
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=voptions_1851
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="16777216"
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("htmlParseChunk")
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_1852
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1024"
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParseChunk")
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_1852
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1024"
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vcur_1856
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="1024"
		and target_2.getParent().(WhileStmt).getCondition()=target_1
}

predicate func_3(Function func, WhileStmt target_3) {
		target_3.getCondition() instanceof RelationalOperation
		and target_3.getStmt() instanceof BlockStmt
		and target_3.getEnclosingFunction() = func
}

from Function func, Parameter voptions_1851, Variable vctxt_1852, Variable vsize_1855, Variable vcur_1856, RelationalOperation target_1, BlockStmt target_2, WhileStmt target_3
where
not func_0(func)
and func_1(vsize_1855, vcur_1856, target_1)
and func_2(voptions_1851, vctxt_1852, vsize_1855, vcur_1856, target_1, target_2)
and func_3(func, target_3)
and voptions_1851.getType().hasName("int")
and vctxt_1852.getType().hasName("xmlParserCtxtPtr")
and vsize_1855.getType().hasName("int")
and vcur_1856.getType().hasName("int")
and voptions_1851.getFunction() = func
and vctxt_1852.(LocalVariable).getFunction() = func
and vsize_1855.(LocalVariable).getFunction() = func
and vcur_1856.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
