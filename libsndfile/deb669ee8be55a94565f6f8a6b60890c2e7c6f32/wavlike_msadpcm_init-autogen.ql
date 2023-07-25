/**
 * @name libsndfile-deb669ee8be55a94565f6f8a6b60890c2e7c6f32-wavlike_msadpcm_init
 * @id cpp/libsndfile/deb669ee8be55a94565f6f8a6b60890c2e7c6f32/wavlike-msadpcm-init
 * @description libsndfile-deb669ee8be55a94565f6f8a6b60890c2e7c6f32-src/ms_adpcm.c-wavlike_msadpcm_init CVE-2021-3246
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpsf_118, Parameter vblockalign_118, BlockStmt target_5, ExprStmt target_6, ExprStmt target_7, VariableAccess target_0) {
		target_0.getTarget()=vblockalign_118
		and target_0.getParent().(LTExpr).getGreaterOperand().(MulExpr).getLeftOperand().(Literal).getValue()="7"
		and target_0.getParent().(LTExpr).getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_0.getParent().(LTExpr).getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_0.getParent().(LTExpr).getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_118
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_5
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(LTExpr).getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getParent().(LTExpr).getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

/*predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="*** Error blockalign (%d) should be > %d.\n"
		and not target_1.getValue()="*** Error samplesperblock (%d) should be >= %d.\n"
		and target_1.getEnclosingFunction() = func
}

*/
predicate func_2(Parameter vpsf_118, Parameter vblockalign_118, RelationalOperation target_8, VariableAccess target_2) {
		target_2.getTarget()=vblockalign_118
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("psf_log_printf")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpsf_118
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*** Error blockalign (%d) should be > %d.\n"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getLeftOperand().(Literal).getValue()="7"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_118
		and target_8.getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_3(Parameter vpsf_118, Parameter vblockalign_118, Parameter vsamplesperblock_118, MulExpr target_9, ExprStmt target_7, ExprStmt target_10, ExprStmt target_6, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vblockalign_118
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vsamplesperblock_118
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_118
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("psf_log_printf")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpsf_118
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*** Error blockalign (%d) should be >= %d.\n"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vblockalign_118
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vsamplesperblock_118
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(DivExpr).getRightOperand().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_3)
		and target_9.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vpsf_118, Parameter vblockalign_118, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("psf_log_printf")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpsf_118
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vblockalign_118
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getLeftOperand().(Literal).getValue()="7"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_118
}

predicate func_6(Parameter vpsf_118, Parameter vblockalign_118, Parameter vsamplesperblock_118, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsamplesperblock_118
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vblockalign_118
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_118
}

predicate func_7(Parameter vpsf_118, Parameter vblockalign_118, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("psf_log_printf")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpsf_118
		and target_7.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vblockalign_118
		and target_7.getExpr().(FunctionCall).getArgument(3).(MulExpr).getLeftOperand().(Literal).getValue()="7"
		and target_7.getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_7.getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_7.getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_118
}

predicate func_8(Parameter vpsf_118, Parameter vblockalign_118, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vblockalign_118
		and target_8.getGreaterOperand().(MulExpr).getLeftOperand().(Literal).getValue()="7"
		and target_8.getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_8.getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_8.getGreaterOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_118
}

predicate func_9(Parameter vpsf_118, MulExpr target_9) {
		target_9.getLeftOperand().(Literal).getValue()="7"
		and target_9.getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_9.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_9.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_118
}

predicate func_10(Parameter vblockalign_118, Parameter vsamplesperblock_118, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="56"
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vblockalign_118
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sf"
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vsamplesperblock_118
}

from Function func, Parameter vpsf_118, Parameter vblockalign_118, Parameter vsamplesperblock_118, VariableAccess target_0, VariableAccess target_2, BlockStmt target_5, ExprStmt target_6, ExprStmt target_7, RelationalOperation target_8, MulExpr target_9, ExprStmt target_10
where
func_0(vpsf_118, vblockalign_118, target_5, target_6, target_7, target_0)
and func_2(vpsf_118, vblockalign_118, target_8, target_2)
and not func_3(vpsf_118, vblockalign_118, vsamplesperblock_118, target_9, target_7, target_10, target_6, func)
and func_5(vpsf_118, vblockalign_118, target_5)
and func_6(vpsf_118, vblockalign_118, vsamplesperblock_118, target_6)
and func_7(vpsf_118, vblockalign_118, target_7)
and func_8(vpsf_118, vblockalign_118, target_8)
and func_9(vpsf_118, target_9)
and func_10(vblockalign_118, vsamplesperblock_118, target_10)
and vpsf_118.getType().hasName("SF_PRIVATE *")
and vblockalign_118.getType().hasName("int")
and vsamplesperblock_118.getType().hasName("int")
and vpsf_118.getParentScope+() = func
and vblockalign_118.getParentScope+() = func
and vsamplesperblock_118.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
