/**
 * @name haproxy-146f53ae7e97dbfe496d0445c2802dd0a30b0878-h2_make_htx_trailers
 * @id cpp/haproxy/146f53ae7e97dbfe496d0445c2802dd0a30b0878/h2-make-htx-trailers
 * @description haproxy-146f53ae7e97dbfe496d0445c2802dd0a30b0878-src/h2.c-h2_make_htx_trailers CVE-2019-19330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="32"
		and target_0.getParent().(NEExpr).getParent().(IfStmt).getCondition() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vi_713, GotoStmt target_6, PostfixIncrExpr target_7, RelationalOperation target_3) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand() instanceof RelationalOperation
		and target_1.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const uint8_t[256]")
		and target_1.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="ptr"
		and target_1.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="n"
		and target_1.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_713
		and target_1.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="32"
		and target_1.getParent().(IfStmt).getThen()=target_6
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_1.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_2(Variable vidx_712, Parameter vlist_709, ArrayExpr target_2) {
		target_2.getArrayBase().(VariableAccess).getTarget()=vlist_709
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vidx_712
}

predicate func_3(Variable vidx_712, Variable vi_713, Parameter vlist_709, GotoStmt target_6, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="ptr"
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="n"
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlist_709
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_712
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_713
		and target_3.getLesserOperand().(SubExpr).getRightOperand().(CharLiteral).getValue()="65"
		and target_3.getGreaterOperand().(SubExpr).getValue()="25"
		and target_3.getParent().(IfStmt).getThen()=target_6
}

predicate func_4(Function func, IfStmt target_4) {
		target_4.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("h2_str_to_phdr")
		and target_4.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="n"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier() instanceof ArrayExpr
		and target_4.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_4.getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_4.getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="fail"
		and target_4.getEnclosingFunction() = func
}

/*predicate func_5(EqualityOperation target_8, Function func, GotoStmt target_5) {
		target_5.toString() = "goto ..."
		and target_5.getName() ="fail"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_5.getEnclosingFunction() = func
}

*/
predicate func_6(GotoStmt target_6) {
		target_6.toString() = "goto ..."
		and target_6.getName() ="fail"
}

predicate func_7(Variable vi_713, PostfixIncrExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vi_713
}

predicate func_8(EqualityOperation target_8) {
		target_8.getAnOperand() instanceof FunctionCall
		and target_8.getAnOperand() instanceof Literal
}

from Function func, Variable vidx_712, Variable vi_713, Parameter vlist_709, Literal target_0, ArrayExpr target_2, RelationalOperation target_3, IfStmt target_4, GotoStmt target_6, PostfixIncrExpr target_7, EqualityOperation target_8
where
func_0(func, target_0)
and not func_1(vi_713, target_6, target_7, target_3)
and func_2(vidx_712, vlist_709, target_2)
and func_3(vidx_712, vi_713, vlist_709, target_6, target_3)
and func_4(func, target_4)
and func_6(target_6)
and func_7(vi_713, target_7)
and func_8(target_8)
and vidx_712.getType().hasName("uint32_t")
and vi_713.getType().hasName("int")
and vlist_709.getType().hasName("http_hdr *")
and vidx_712.getParentScope+() = func
and vi_713.getParentScope+() = func
and vlist_709.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
