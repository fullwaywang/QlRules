/**
 * @name openssl-c0334c2c92dd1bc3ad8138ba6e74006c3631b0f9-PKCS7_dataFinal
 * @id cpp/openssl/c0334c2c92dd1bc3ad8138ba6e74006c3631b0f9/PKCS7-dataFinal
 * @description openssl-c0334c2c92dd1bc3ad8138ba6e74006c3631b0f9-PKCS7_dataFinal CVE-2015-0289
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vp7_699) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vp7_699
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_2(Parameter vp7_699, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ptr"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp7_699
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_2))
}

predicate func_5(Parameter vp7_699, Variable vos_708) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vos_708
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("OBJ_obj2nid")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="21"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="detached"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp7_699)
}

predicate func_7(Variable vi_702) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_7.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vi_702)
}

predicate func_8(Variable vbtmp_703, Variable vos_708, Variable vcont_824, Variable vcontlen_825, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition() instanceof NotExpr
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vos_708
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition() instanceof NotExpr
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof LongType
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbtmp_703
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BIO_find_type")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbtmp_703
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcontlen_825
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BIO_ctrl")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BIO_set_flags")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbtmp_703
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="512"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BIO_ctrl")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbtmp_703
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="130"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ASN1_STRING_set0")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vos_708
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcont_824
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcontlen_825
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_8))
}

predicate func_11(Parameter vp7_699, Variable vos_708) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(FunctionCall).getTarget().hasName("ASN1_STRING_free")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vos_708
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("OBJ_obj2nid")
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="type"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="21"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="detached"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp7_699)
}

predicate func_12(Parameter vp7_699) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="contents"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="sign"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("OBJ_obj2nid")
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="type"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="21"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="detached"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp7_699)
}

predicate func_14(Parameter vp7_699) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="contents"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="digest"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_14.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("OBJ_obj2nid")
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="type"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="21"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="detached"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp7_699)
}

predicate func_17(Parameter vbio_699, Variable vbtmp_703) {
	exists(LogicalAndExpr target_17 |
		target_17.getAnOperand() instanceof NotExpr
		and target_17.getAnOperand() instanceof NotExpr
		and target_17.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and target_17.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof LongType
		and target_17.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbtmp_703
		and target_17.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BIO_find_type")
		and target_17.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbio_699)
}

predicate func_18(Parameter vp7_699) {
	exists(ValueFieldAccess target_18 |
		target_18.getTarget().getName()="digest"
		and target_18.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp7_699)
}

predicate func_19(Variable vos_708) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("ASN1_STRING_free")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vos_708)
}

predicate func_21(Variable vos_708, Variable vcont_824, Variable vcontlen_825) {
	exists(FunctionCall target_21 |
		target_21.getTarget().hasName("ASN1_STRING_set0")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vos_708
		and target_21.getArgument(1).(VariableAccess).getTarget()=vcont_824
		and target_21.getArgument(2).(VariableAccess).getTarget()=vcontlen_825)
}

from Function func, Parameter vp7_699, Parameter vbio_699, Variable vi_702, Variable vbtmp_703, Variable vos_708, Variable vcont_824, Variable vcontlen_825
where
not func_1(vp7_699)
and not func_2(vp7_699, func)
and not func_5(vp7_699, vos_708)
and not func_7(vi_702)
and not func_8(vbtmp_703, vos_708, vcont_824, vcontlen_825, func)
and func_11(vp7_699, vos_708)
and func_12(vp7_699)
and func_14(vp7_699)
and func_17(vbio_699, vbtmp_703)
and vp7_699.getType().hasName("PKCS7 *")
and func_18(vp7_699)
and vbio_699.getType().hasName("BIO *")
and vi_702.getType().hasName("int")
and vbtmp_703.getType().hasName("BIO *")
and vos_708.getType().hasName("ASN1_OCTET_STRING *")
and func_19(vos_708)
and func_21(vos_708, vcont_824, vcontlen_825)
and vcont_824.getType().hasName("char *")
and vcontlen_825.getType().hasName("long")
and vp7_699.getParentScope+() = func
and vbio_699.getParentScope+() = func
and vi_702.getParentScope+() = func
and vbtmp_703.getParentScope+() = func
and vos_708.getParentScope+() = func
and vcont_824.getParentScope+() = func
and vcontlen_825.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
