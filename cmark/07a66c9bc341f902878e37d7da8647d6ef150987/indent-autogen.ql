/**
 * @name cmark-07a66c9bc341f902878e37d7da8647d6ef150987-indent
 * @id cpp/cmark/07a66c9bc341f902878e37d7da8647d6ef150987/indent
 * @description cmark-07a66c9bc341f902878e37d7da8647d6ef150987-src/xml.c-indent CVE-2023-26485
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_28, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_28
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="40"
		and target_0.getParent().(ForStmt).getStmt()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vstate_27, Variable vi_28, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vi_28
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="indent"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_27
		and target_1.getParent().(ForStmt).getStmt()=target_2
}

predicate func_2(Parameter vstate_27, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cmark_strbuf_putc")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="xml"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_27
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="32"
}

predicate func_3(Variable vi_28, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_28
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vstate_27, Variable vi_28, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vi_28, target_2, target_3, target_1)
and func_1(vstate_27, vi_28, target_2, target_1)
and func_2(vstate_27, target_2)
and func_3(vi_28, target_3)
and vstate_27.getType().hasName("render_state *")
and vi_28.getType().hasName("int")
and vstate_27.getParentScope+() = func
and vi_28.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
