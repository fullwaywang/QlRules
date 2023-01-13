/**
 * @name libexpat-3f0a0cb644438d4d8e3294cd0b1245d0edb0c6c6-normal_prologTok
 * @id cpp/libexpat/3f0a0cb644438d4d8e3294cd0b1245d0edb0c6c6/normal-prologTok
 * @description libexpat-3f0a0cb644438d4d8e3294cd0b1245d0edb0c6c6-normal_prologTok CVE-2022-25235
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter venc_1015, Parameter vptr_1015) {
	exists(VariableCall target_0 |
		target_0.getExpr().(PointerFieldAccess).getTarget().getName()="isInvalid2"
		and target_0.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_0.getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_0.getArgument(1).(VariableAccess).getTarget()=vptr_1015)
}

predicate func_1(Parameter venc_1015, Parameter vptr_1015) {
	exists(VariableCall target_1 |
		target_1.getExpr().(PointerFieldAccess).getTarget().getName()="isInvalid3"
		and target_1.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_1.getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_1.getArgument(1).(VariableAccess).getTarget()=vptr_1015)
}

predicate func_2(Parameter venc_1015, Parameter vptr_1015) {
	exists(VariableCall target_2 |
		target_2.getExpr().(PointerFieldAccess).getTarget().getName()="isInvalid4"
		and target_2.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_2.getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_2.getArgument(1).(VariableAccess).getTarget()=vptr_1015)
}

predicate func_4(Parameter venc_1015, Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(LogicalOrExpr target_4 |
		target_4.getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="isInvalid2"
		and target_4.getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_4.getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_4.getAnOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vptr_1015
		and target_4.getAnOperand() instanceof NotExpr
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_5(Parameter venc_1015, Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(LogicalOrExpr target_5 |
		target_5.getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="isInvalid3"
		and target_5.getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_5.getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_5.getAnOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vptr_1015
		and target_5.getAnOperand() instanceof NotExpr
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_6(Parameter venc_1015, Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(LogicalOrExpr target_6 |
		target_6.getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="isInvalid4"
		and target_6.getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_6.getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_6.getAnOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vptr_1015
		and target_6.getAnOperand() instanceof NotExpr
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_8(Parameter venc_1015, Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="isInvalid2"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vptr_1015
		and target_8.getCondition().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015
		and target_8.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_11(Parameter venc_1015, Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(IfStmt target_11 |
		target_11.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="isInvalid3"
		and target_11.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_11.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_11.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vptr_1015
		and target_11.getCondition().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015
		and target_11.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_14(Parameter venc_1015, Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(IfStmt target_14 |
		target_14.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="isInvalid4"
		and target_14.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_14.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_14.getCondition().(LogicalOrExpr).getAnOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vptr_1015
		and target_14.getCondition().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015
		and target_14.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_23(Parameter venc_1015, Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(NotExpr target_23 |
		target_23.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="isName2"
		and target_23.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_23.getOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_23.getOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vptr_1015
		and target_23.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_23.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015
		and target_23.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_24(Parameter venc_1015, Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(NotExpr target_24 |
		target_24.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="isName3"
		and target_24.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_24.getOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_24.getOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vptr_1015
		and target_24.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_24.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015
		and target_24.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_25(Parameter venc_1015, Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(NotExpr target_25 |
		target_25.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="isName4"
		and target_25.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_25.getOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_25.getOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vptr_1015
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_32(Parameter venc_1015) {
	exists(PointerFieldAccess target_32 |
		target_32.getTarget().getName()="type"
		and target_32.getQualifier().(VariableAccess).getTarget()=venc_1015)
}

predicate func_33(Parameter venc_1015, Parameter vptr_1015) {
	exists(VariableCall target_33 |
		target_33.getExpr().(PointerFieldAccess).getTarget().getName()="isName2"
		and target_33.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_33.getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_33.getArgument(1).(VariableAccess).getTarget()=vptr_1015)
}

predicate func_34(Parameter venc_1015, Parameter vptr_1015) {
	exists(VariableCall target_34 |
		target_34.getExpr().(PointerFieldAccess).getTarget().getName()="isName3"
		and target_34.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_1015
		and target_34.getArgument(0).(VariableAccess).getTarget()=venc_1015
		and target_34.getArgument(1).(VariableAccess).getTarget()=vptr_1015)
}

predicate func_38(Parameter vptr_1015, Parameter vend_1015) {
	exists(PointerArithmeticOperation target_38 |
		target_38.getLeftOperand().(VariableAccess).getTarget()=vend_1015
		and target_38.getRightOperand().(VariableAccess).getTarget()=vptr_1015
		and target_38.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="2"
		and target_38.getParent().(LTExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="2")
}

predicate func_41(Parameter vptr_1015) {
	exists(AssignPointerAddExpr target_41 |
		target_41.getLValue().(VariableAccess).getTarget()=vptr_1015
		and target_41.getRValue().(Literal).getValue()="4")
}

predicate func_43(Parameter vptr_1015) {
	exists(AssignPointerAddExpr target_43 |
		target_43.getLValue().(VariableAccess).getTarget()=vptr_1015
		and target_43.getRValue().(Literal).getValue()="2")
}

predicate func_45(Parameter vptr_1015) {
	exists(AssignPointerAddExpr target_45 |
		target_45.getLValue().(VariableAccess).getTarget()=vptr_1015
		and target_45.getRValue().(Literal).getValue()="3")
}

predicate func_47(Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(PointerArithmeticOperation target_47 |
		target_47.getAnOperand().(VariableAccess).getTarget()=vptr_1015
		and target_47.getAnOperand().(Literal).getValue()="1"
		and target_47.getParent().(AssignExpr).getRValue() = target_47
		and target_47.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016)
}

predicate func_48(Parameter vptr_1015, Parameter vnextTokPtr_1016) {
	exists(PointerDereferenceExpr target_48 |
		target_48.getOperand().(VariableAccess).getTarget()=vnextTokPtr_1016
		and target_48.getParent().(AssignExpr).getLValue() = target_48
		and target_48.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_1015)
}

from Function func, Parameter venc_1015, Parameter vptr_1015, Parameter vend_1015, Parameter vnextTokPtr_1016
where
not func_0(venc_1015, vptr_1015)
and not func_1(venc_1015, vptr_1015)
and not func_2(venc_1015, vptr_1015)
and not func_4(venc_1015, vptr_1015, vnextTokPtr_1016)
and not func_5(venc_1015, vptr_1015, vnextTokPtr_1016)
and not func_6(venc_1015, vptr_1015, vnextTokPtr_1016)
and not func_8(venc_1015, vptr_1015, vnextTokPtr_1016)
and not func_11(venc_1015, vptr_1015, vnextTokPtr_1016)
and not func_14(venc_1015, vptr_1015, vnextTokPtr_1016)
and func_23(venc_1015, vptr_1015, vnextTokPtr_1016)
and func_24(venc_1015, vptr_1015, vnextTokPtr_1016)
and func_25(venc_1015, vptr_1015, vnextTokPtr_1016)
and venc_1015.getType().hasName("const ENCODING *")
and func_32(venc_1015)
and func_33(venc_1015, vptr_1015)
and func_34(venc_1015, vptr_1015)
and vptr_1015.getType().hasName("const char *")
and func_38(vptr_1015, vend_1015)
and func_41(vptr_1015)
and func_43(vptr_1015)
and func_45(vptr_1015)
and func_47(vptr_1015, vnextTokPtr_1016)
and vend_1015.getType().hasName("const char *")
and vnextTokPtr_1016.getType().hasName("const char **")
and func_48(vptr_1015, vnextTokPtr_1016)
and venc_1015.getParentScope+() = func
and vptr_1015.getParentScope+() = func
and vend_1015.getParentScope+() = func
and vnextTokPtr_1016.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
