/**
 * @name ffmpeg-77d2ef13a8fa630e5081f14bde3fd20f84c90aec-ebml_parse_elem
 * @id cpp/ffmpeg/77d2ef13a8fa630e5081f14bde3fd20f84c90aec/ebml-parse-elem
 * @description ffmpeg-77d2ef13a8fa630e5081f14bde3fd20f84c90aec-libavformat/matroskadec.c-ebml_parse_elem CVE-2011-3504
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(PointerFieldAccess target_4, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("void *")
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vlist_807, PointerFieldAccess target_4) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="elem"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlist_807
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("void *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4)
}

predicate func_3(Variable vlist_807, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="elem"
		and target_3.getQualifier().(VariableAccess).getTarget()=vlist_807
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_realloc")
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="elem"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlist_807
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="nb_elem"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlist_807
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="list_elem_size"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("EbmlSyntax *")
}

predicate func_4(PointerFieldAccess target_4) {
		target_4.getTarget().getName()="list_elem_size"
		and target_4.getQualifier().(VariableAccess).getTarget().getType().hasName("EbmlSyntax *")
}

from Function func, Variable vlist_807, PointerFieldAccess target_3, PointerFieldAccess target_4
where
not func_1(target_4, func)
and not func_2(vlist_807, target_4)
and func_3(vlist_807, target_3)
and func_4(target_4)
and vlist_807.getType().hasName("EbmlList *")
and vlist_807.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
