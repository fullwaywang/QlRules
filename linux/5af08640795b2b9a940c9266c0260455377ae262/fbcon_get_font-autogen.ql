/**
 * @name linux-5af08640795b2b9a940c9266c0260455377ae262-fbcon_get_font
 * @id cpp/linux/5af08640795b2b9a940c9266c0260455377ae262/fbcon_get_font
 * @description linux-5af08640795b2b9a940c9266c0260455377ae262-fbcon_get_font 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vfont_2460, Variable vfontdata_2462, Variable vj_2464) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="charcount"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_2460
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vj_2464
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfontdata_2462
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-2"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(Literal).getValue()="2"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_2460
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8")
}

predicate func_2(Parameter vvc_2460, Parameter vfont_2460, Variable vfontdata_2462) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="charcount"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_2460
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="height"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vc_font"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvc_2460
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfontdata_2462
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-2"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(Literal).getValue()="2"
		and target_2.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_2.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_2460
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="24")
}

predicate func_4(Parameter vvc_2460) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="vc_font"
		and target_4.getQualifier().(VariableAccess).getTarget()=vvc_2460)
}

predicate func_5(Parameter vfont_2460) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="width"
		and target_5.getQualifier().(VariableAccess).getTarget()=vfont_2460)
}

predicate func_8(Parameter vfont_2460) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="charcount"
		and target_8.getQualifier().(VariableAccess).getTarget()=vfont_2460)
}

predicate func_9(Variable vfontdata_2462, Variable vj_2464) {
	exists(AssignPointerAddExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=vfontdata_2462
		and target_9.getRValue().(VariableAccess).getTarget()=vj_2464)
}

predicate func_11(Variable vfontdata_2462) {
	exists(AssignPointerAddExpr target_11 |
		target_11.getLValue().(VariableAccess).getTarget()=vfontdata_2462
		and target_11.getRValue().(SizeofTypeOperator).getType() instanceof LongType
		and target_11.getRValue().(SizeofTypeOperator).getValue()="4")
}

predicate func_12(Parameter vvc_2460, Variable vj_2464) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(VariableAccess).getTarget()=vj_2464
		and target_12.getRValue().(ValueFieldAccess).getTarget().getName()="height"
		and target_12.getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vc_font"
		and target_12.getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvc_2460)
}

predicate func_13(Parameter vvc_2460, Variable vj_2464) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(VariableAccess).getTarget()=vj_2464
		and target_13.getRValue().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="height"
		and target_13.getRValue().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vc_font"
		and target_13.getRValue().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvc_2460
		and target_13.getRValue().(MulExpr).getRightOperand().(Literal).getValue()="2")
}

predicate func_14(Parameter vvc_2460, Variable vj_2464) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(VariableAccess).getTarget()=vj_2464
		and target_14.getRValue().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="height"
		and target_14.getRValue().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vc_font"
		and target_14.getRValue().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvc_2460
		and target_14.getRValue().(MulExpr).getRightOperand().(Literal).getValue()="4")
}

from Function func, Parameter vvc_2460, Parameter vfont_2460, Variable vfontdata_2462, Variable vj_2464
where
not func_0(vfont_2460, vfontdata_2462, vj_2464)
and not func_2(vvc_2460, vfont_2460, vfontdata_2462)
and vvc_2460.getType().hasName("vc_data *")
and func_4(vvc_2460)
and vfont_2460.getType().hasName("console_font *")
and func_5(vfont_2460)
and func_8(vfont_2460)
and vfontdata_2462.getType().hasName("u8 *")
and func_9(vfontdata_2462, vj_2464)
and func_11(vfontdata_2462)
and vj_2464.getType().hasName("int")
and func_12(vvc_2460, vj_2464)
and func_13(vvc_2460, vj_2464)
and func_14(vvc_2460, vj_2464)
and vvc_2460.getParentScope+() = func
and vfont_2460.getParentScope+() = func
and vfontdata_2462.getParentScope+() = func
and vj_2464.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
