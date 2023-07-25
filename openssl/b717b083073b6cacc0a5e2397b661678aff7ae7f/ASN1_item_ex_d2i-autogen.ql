/**
 * @name openssl-b717b083073b6cacc0a5e2397b661678aff7ae7f-ASN1_item_ex_d2i
 * @id cpp/openssl/b717b083073b6cacc0a5e2397b661678aff7ae7f/ASN1-item-ex-d2i
 * @description openssl-b717b083073b6cacc0a5e2397b661678aff7ae7f-ASN1_item_ex_d2i CVE-2015-0287
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpval_165, Parameter vit_166, Variable vi_179) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_179
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("asn1_get_choice_selector")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vit_166
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof PointerDereferenceExpr)
}

predicate func_1(Parameter vpval_165, Parameter vit_166, Variable vtt_169, Variable vi_179, Variable vpchptr_182) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_179
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtt_169
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="templates"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit_166
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_179
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpchptr_182
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("asn1_get_field_ptr")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtt_169
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ASN1_template_free")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpchptr_182
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtt_169
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("asn1_set_choice_selector")
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vit_166
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof PointerDereferenceExpr)
}

predicate func_6(Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition() instanceof NotExpr
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_6.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_6.getParent().(IfStmt).getCondition() instanceof PointerDereferenceExpr
		and target_6.getEnclosingFunction() = func)
}

predicate func_8(Parameter vit_166, Variable vtt_169, Variable vi_179, Variable vpseqval_1_392) {
	exists(ForStmt target_8 |
		target_8.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_179
		and target_8.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtt_169
		and target_8.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="templates"
		and target_8.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit_166
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_179
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tcount"
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit_166
		and target_8.getUpdate().(CommaExpr).getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_179
		and target_8.getUpdate().(CommaExpr).getRightOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vtt_169
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_169
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="768"
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof DeclStmt
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpseqval_1_392
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("asn1_get_field_ptr")
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ASN1_template_free")
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("ASN1_VALUE **")
		and target_8.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const ASN1_TEMPLATE *")
		and target_8.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="itype"
		and target_8.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit_166)
}

predicate func_19(Parameter vpval_165, Parameter vlen_165, Parameter vit_166, Parameter vctx_167, Variable vtt_169, Variable vi_179, Variable vret_181, Variable vpchptr_182) {
	exists(RelationalOperation target_19 |
		 (target_19 instanceof GTExpr or target_19 instanceof LTExpr)
		and target_19.getLesserOperand().(VariableAccess).getTarget()=vi_179
		and target_19.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tcount"
		and target_19.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit_166
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpchptr_182
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("asn1_get_field_ptr")
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtt_169
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_181
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("asn1_template_ex_d2i")
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpchptr_182
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_165
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtt_169
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="1"
		and target_19.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vctx_167)
}

predicate func_20(Parameter vpval_165) {
	exists(PointerDereferenceExpr target_20 |
		target_20.getOperand().(VariableAccess).getTarget()=vpval_165)
}

predicate func_21(Parameter vpval_165, Parameter vit_166) {
	exists(NotExpr target_21 |
		target_21.getOperand().(FunctionCall).getTarget().hasName("ASN1_item_ex_new")
		and target_21.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_21.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vit_166
		and target_21.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_21.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_21.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_21.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_21.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_21.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_22(Function func) {
	exists(DeclStmt target_22 |
		target_22.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(Parameter vpval_165, Variable vtt_169, Variable vseqtt_391) {
	exists(ExprStmt target_23 |
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vseqtt_391
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("asn1_do_adb")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtt_169
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1")
}

predicate func_24(Function func) {
	exists(NotExpr target_24 |
		target_24.getOperand() instanceof PointerDereferenceExpr
		and target_24.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_24.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_24.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_24.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_24.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_24.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_24.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_24.getEnclosingFunction() = func)
}

predicate func_25(Parameter vpval_165, Parameter vit_166) {
	exists(LogicalAndExpr target_25 |
		target_25.getAnOperand().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpval_165
		and target_25.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ASN1_item_ex_new")
		and target_25.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_25.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vit_166
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_26(Function func) {
	exists(LogicalAndExpr target_26 |
		target_26.getAnOperand() instanceof NotExpr
		and target_26.getAnOperand() instanceof NotExpr
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_26.getEnclosingFunction() = func)
}

predicate func_27(Parameter vpval_165, Variable vtt_169, Variable vseqtt_391) {
	exists(AssignExpr target_27 |
		target_27.getLValue().(VariableAccess).getTarget()=vseqtt_391
		and target_27.getRValue().(FunctionCall).getTarget().hasName("asn1_do_adb")
		and target_27.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_27.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtt_169
		and target_27.getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1")
}

predicate func_28(Parameter vpval_165, Variable vseqtt_391, Variable vpseqval_1_392) {
	exists(AssignExpr target_28 |
		target_28.getLValue().(VariableAccess).getTarget()=vpseqval_1_392
		and target_28.getRValue().(FunctionCall).getTarget().hasName("asn1_get_field_ptr")
		and target_28.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_28.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vseqtt_391)
}

predicate func_30(Parameter vpval_165, Parameter vit_166, Variable vasn1_cb_173) {
	exists(LogicalAndExpr target_30 |
		target_30.getAnOperand().(VariableAccess).getTarget()=vasn1_cb_173
		and target_30.getAnOperand().(NotExpr).getOperand().(VariableCall).getExpr().(VariableAccess).getTarget()=vasn1_cb_173
		and target_30.getAnOperand().(NotExpr).getOperand().(VariableCall).getArgument(0).(Literal).getValue()="4"
		and target_30.getAnOperand().(NotExpr).getOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vpval_165
		and target_30.getAnOperand().(NotExpr).getOperand().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vit_166
		and target_30.getAnOperand().(NotExpr).getOperand().(VariableCall).getArgument(3).(Literal).getValue()="0"
		and target_30.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_31(Parameter vit_166, Variable vtt_169, Variable vi_179) {
	exists(CommaExpr target_31 |
		target_31.getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_179
		and target_31.getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_31.getRightOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtt_169
		and target_31.getRightOperand().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="templates"
		and target_31.getRightOperand().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit_166)
}

predicate func_32(Parameter vit_166, Variable visopt_177, Variable vi_179) {
	exists(EqualityOperation target_32 |
		target_32.getAnOperand().(VariableAccess).getTarget()=vi_179
		and target_32.getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tcount"
		and target_32.getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit_166
		and target_32.getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_32.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=visopt_177
		and target_32.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_33(Variable vtt_169, Variable vi_179) {
	exists(CommaExpr target_33 |
		target_33.getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_179
		and target_33.getRightOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vtt_169)
}

predicate func_34(Variable vtt_169, Variable vi_179) {
	exists(CommaExpr target_34 |
		target_34.getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vtt_169
		and target_34.getRightOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_179)
}

predicate func_35(Parameter vpval_165, Parameter vit_166, Variable vi_179) {
	exists(FunctionCall target_35 |
		target_35.getTarget().hasName("asn1_set_choice_selector")
		and target_35.getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_35.getArgument(1).(VariableAccess).getTarget()=vi_179
		and target_35.getArgument(2).(VariableAccess).getTarget()=vit_166)
}

predicate func_38(Parameter vlen_165, Parameter vctx_167, Variable vtt_169, Variable vp_174, Variable vret_181, Variable vpchptr_182) {
	exists(AssignExpr target_38 |
		target_38.getLValue().(VariableAccess).getTarget()=vret_181
		and target_38.getRValue().(FunctionCall).getTarget().hasName("asn1_template_ex_d2i")
		and target_38.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpchptr_182
		and target_38.getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_174
		and target_38.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_165
		and target_38.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtt_169
		and target_38.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="1"
		and target_38.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vctx_167)
}

predicate func_39(Variable vseqtt_391) {
	exists(NotExpr target_39 |
		target_39.getOperand().(VariableAccess).getTarget()=vseqtt_391
		and target_39.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

from Function func, Parameter vpval_165, Parameter vlen_165, Parameter vit_166, Parameter vctx_167, Variable vtt_169, Variable vasn1_cb_173, Variable vp_174, Variable visopt_177, Variable vi_179, Variable vret_181, Variable vpchptr_182, Variable vseqtt_391, Variable vpseqval_1_392, Variable vseqtt_1_457
where
not func_0(vpval_165, vit_166, vi_179)
and not func_1(vpval_165, vit_166, vtt_169, vi_179, vpchptr_182)
and not func_6(func)
and not func_8(vit_166, vtt_169, vi_179, vpseqval_1_392)
and func_19(vpval_165, vlen_165, vit_166, vctx_167, vtt_169, vi_179, vret_181, vpchptr_182)
and func_20(vpval_165)
and func_21(vpval_165, vit_166)
and func_22(func)
and func_23(vpval_165, vtt_169, vseqtt_391)
and func_24(func)
and vpval_165.getType().hasName("ASN1_VALUE **")
and func_25(vpval_165, vit_166)
and func_26(func)
and func_27(vpval_165, vtt_169, vseqtt_391)
and func_28(vpval_165, vseqtt_391, vpseqval_1_392)
and vlen_165.getType().hasName("long")
and vit_166.getType().hasName("const ASN1_ITEM *")
and func_30(vpval_165, vit_166, vasn1_cb_173)
and func_31(vit_166, vtt_169, vi_179)
and func_32(vit_166, visopt_177, vi_179)
and vctx_167.getType().hasName("ASN1_TLC *")
and vtt_169.getType().hasName("const ASN1_TEMPLATE *")
and func_33(vtt_169, vi_179)
and func_34(vtt_169, vi_179)
and vasn1_cb_173.getType().hasName("ASN1_aux_cb *")
and visopt_177.getType().hasName("char")
and vi_179.getType().hasName("int")
and func_35(vpval_165, vit_166, vi_179)
and vret_181.getType().hasName("int")
and vpchptr_182.getType().hasName("ASN1_VALUE **")
and func_38(vlen_165, vctx_167, vtt_169, vp_174, vret_181, vpchptr_182)
and vseqtt_391.getType().hasName("const ASN1_TEMPLATE *")
and func_39(vseqtt_391)
and vpseqval_1_392.getType().hasName("ASN1_VALUE **")
and vpval_165.getParentScope+() = func
and vlen_165.getParentScope+() = func
and vit_166.getParentScope+() = func
and vctx_167.getParentScope+() = func
and vtt_169.getParentScope+() = func
and vasn1_cb_173.getParentScope+() = func
and vp_174.getParentScope+() = func
and visopt_177.getParentScope+() = func
and vi_179.getParentScope+() = func
and vret_181.getParentScope+() = func
and vpchptr_182.getParentScope+() = func
and vseqtt_391.getParentScope+() = func
and vpseqval_1_392.getParentScope+() = func
and vseqtt_1_457.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
