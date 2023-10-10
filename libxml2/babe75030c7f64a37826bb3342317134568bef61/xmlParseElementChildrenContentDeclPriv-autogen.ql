/**
 * @name libxml2-babe75030c7f64a37826bb3342317134568bef61-xmlParseElementChildrenContentDeclPriv
 * @id cpp/libxml2/babe75030c7f64a37826bb3342317134568bef61/xmlParseElementChildrenContentDeclPriv
 * @description libxml2-babe75030c7f64a37826bb3342317134568bef61-xmlParseElementChildrenContentDeclPriv CVE-2021-3537
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vdepth_6189, Variable vret_6190, Variable vlast_6190, Variable vinputid_6338, Parameter vctxt_6188) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="id"
		and target_2.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlNextChar")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlSkipBlankChars")
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlast_6190
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlParseElementChildrenContentDeclPriv")
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinputid_6338
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdepth_6189
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlast_6190
		and target_2.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_6190
		and target_2.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFreeDocElementContent")
		and target_2.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="myDoc"
		and target_2.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_2.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vret_6190
		and target_2.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlSkipBlankChars")
		and target_2.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_2.getElse() instanceof BlockStmt)
}

predicate func_7(Variable vret_6190, Variable vlast_6190, Variable velem_6191, Parameter vctxt_6188) {
	exists(BlockStmt target_7 |
		target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=velem_6191
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlParseName")
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=velem_6191
		and target_7.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_6190
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFreeDocElementContent")
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="myDoc"
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vret_6190
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlast_6190
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlNewDocElementContent")
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="myDoc"
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=velem_6191
		and target_7.getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlast_6190
		and target_7.getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_6190
		and target_7.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFreeDocElementContent")
		and target_7.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="myDoc"
		and target_7.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vret_6190
		and target_7.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_7.getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_7.getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="63"
		and target_7.getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ocur"
		and target_7.getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlast_6190
		and target_7.getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlNextChar")
		and target_7.getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="42"
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ocur"
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlast_6190
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlNextChar")
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="43"
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ocur"
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlast_6190
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlNextChar")
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ocur"
		and target_7.getStmt(4).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlast_6190
		and target_7.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_7.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_7.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="40")
}

predicate func_8(Variable vret_6190, Parameter vctxt_6188) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("xmlFreeDocElementContent")
		and target_8.getArgument(0).(PointerFieldAccess).getTarget().getName()="myDoc"
		and target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6188
		and target_8.getArgument(1).(VariableAccess).getTarget()=vret_6190)
}

predicate func_9(Variable vcur_6190, Variable vop_6190) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=vcur_6190
		and target_9.getRValue().(VariableAccess).getTarget()=vop_6190)
}

predicate func_10(Parameter vdepth_6189, Variable vlast_6190, Variable vinputid_6338, Parameter vctxt_6188) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(VariableAccess).getTarget()=vlast_6190
		and target_10.getRValue().(FunctionCall).getTarget().hasName("xmlParseElementChildrenContentDeclPriv")
		and target_10.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_10.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinputid_6338
		and target_10.getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdepth_6189
		and target_10.getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1")
}

predicate func_11(Parameter vdepth_6189, Variable vinputid_6338, Parameter vctxt_6188) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("xmlParseElementChildrenContentDeclPriv")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vctxt_6188
		and target_11.getArgument(1).(VariableAccess).getTarget()=vinputid_6338
		and target_11.getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdepth_6189
		and target_11.getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1")
}

from Function func, Parameter vdepth_6189, Variable vret_6190, Variable vcur_6190, Variable vlast_6190, Variable vop_6190, Variable velem_6191, Variable vinputid_6338, Parameter vctxt_6188
where
not func_2(vdepth_6189, vret_6190, vlast_6190, vinputid_6338, vctxt_6188)
and func_7(vret_6190, vlast_6190, velem_6191, vctxt_6188)
and vdepth_6189.getType().hasName("int")
and vret_6190.getType().hasName("xmlElementContentPtr")
and func_8(vret_6190, vctxt_6188)
and vcur_6190.getType().hasName("xmlElementContentPtr")
and func_9(vcur_6190, vop_6190)
and vlast_6190.getType().hasName("xmlElementContentPtr")
and func_10(vdepth_6189, vlast_6190, vinputid_6338, vctxt_6188)
and vop_6190.getType().hasName("xmlElementContentPtr")
and velem_6191.getType().hasName("const xmlChar *")
and vinputid_6338.getType().hasName("int")
and vctxt_6188.getType().hasName("xmlParserCtxtPtr")
and func_11(vdepth_6189, vinputid_6338, vctxt_6188)
and vdepth_6189.getParentScope+() = func
and vret_6190.getParentScope+() = func
and vcur_6190.getParentScope+() = func
and vlast_6190.getParentScope+() = func
and vop_6190.getParentScope+() = func
and velem_6191.getParentScope+() = func
and vinputid_6338.getParentScope+() = func
and vctxt_6188.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
