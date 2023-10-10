/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_sta_fixed_rate_set
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7915-sta-fixed-rate-set
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_sta_fixed_rate_set CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_484) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vdata_484)
}

predicate func_1(Parameter vrate_484, Variable vsta_486) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("mt7915_mcu_set_fixed_rate")
		and not target_1.getTarget().hasName("sscanf")
		and target_1.getArgument(0) instanceof PointerFieldAccess
		and target_1.getArgument(1).(VariableAccess).getTarget()=vsta_486
		and target_1.getArgument(2).(VariableAccess).getTarget()=vrate_484)
}

predicate func_2(Function func) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="private_data"
		and target_2.getQualifier().(VariableAccess).getType().hasName("file *")
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof PointerFieldAccess
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_3)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_4)
}

predicate func_5(Function func) {
	exists(DeclStmt target_5 |
		target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ClassAggregateLiteral).getValue()="{...}"
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_5)
}

predicate func_6(Function func) {
	exists(DeclStmt target_6 |
		target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof ArrayType
		and func.getEntryPoint().(BlockStmt).getStmt(5)=target_6)
}

predicate func_7(Function func) {
	exists(DeclStmt target_7 |
		func.getEntryPoint().(BlockStmt).getStmt(6)=target_7)
}

predicate func_8(Function func) {
	exists(DeclStmt target_8 |
		target_8.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getStmt(7)=target_8)
}

predicate func_9(Function func) {
	exists(DeclStmt target_9 |
		target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_9.getDeclarationEntry(1).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_9.getDeclarationEntry(2).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getStmt(8)=target_9)
}

predicate func_10(Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="100"
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getType().hasName("char[100]")
		and target_10.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_10.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_10))
}

predicate func_11(Function func) {
	exists(IfStmt target_11 |
		target_11.getCondition().(FunctionCall).getTarget().hasName("copy_from_user")
		and target_11.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[100]")
		and target_11.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char *")
		and target_11.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("size_t")
		and target_11.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-14"
		and target_11.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_11))
}

predicate func_12(Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("char[100]")
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("size_t")
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("char[100]")
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("size_t")
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_12.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("char[100]")
		and target_12.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_12.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_12))
}

predicate func_13(Function func) {
	exists(IfStmt target_13 |
		target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("sscanf")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[100]")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu"
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="bw"
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="nss"
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mcs"
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("u8")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ldpc"
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="stbc"
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(9).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("u8")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ClassAggregateLiteral).getValue()="{...}"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const pi_entry")
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_dev_warn")
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="dev"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("mt7915_dev *")
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="format: Mode BW NSS MCS (HE)GI LDPC STBC HE_LTF\n"
		and target_13.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u32")
		and target_13.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_13))
}

predicate func_32(Function func) {
	exists(ExprStmt target_32 |
		target_32.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ldpc"
		and target_32.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="bw"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="ldpc"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getValue()="7"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="0"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(Literal).getValue()="64"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_32.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_32 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_32))
}

predicate func_33(Variable vsta_486, Function func) {
	exists(ForStmt target_33 |
		target_33.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u8")
		and target_33.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_33.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("u8")
		and target_33.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="bw"
		and target_33.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_33.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("u8")
		and target_33.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getTarget().getName()="sgi"
		and target_33.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_33.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getType().hasName("u8")
		and target_33.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getType().hasName("u8")
		and target_33.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getTarget().getName()="has_he"
		and target_33.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="he_cap"
		and target_33.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsta_486
		and target_33.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getTarget().getName()="he_ltf"
		and target_33.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("sta_phy")
		and target_33.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getType().hasName("u8")
		and target_33.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getType().hasName("u8")
		and target_33.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getTarget().getName()="has_he"
		and target_33.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="he_cap"
		and target_33.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsta_486
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_33 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_33))
}

predicate func_36(Function func) {
	exists(ExprStmt target_36 |
		target_36.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u32")
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_36 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_36))
}

predicate func_37(Function func) {
	exists(LabelStmt target_37 |
		target_37.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_37 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_37))
}

predicate func_38(Variable vmsta_487, Function func) {
	exists(ExprStmt target_38 |
		target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("ieee80211_vif *")
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="vif"
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsta_487
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BuiltInOperation).getChild(0).(TypeName).getType() instanceof VoidType
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BuiltInOperation).getChild(1).(TypeName).getType() instanceof ArrayType
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BuiltInOperation).getChild(0).(TypeName).getType() instanceof VoidType
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BuiltInOperation).getChild(1).(TypeName).getType() instanceof VoidType
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_1781")
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("void *")
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="drv_priv"
		and target_38.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_38 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_38))
}

predicate func_44(Variable vsta_486, Function func) {
	exists(ExprStmt target_44 |
		target_44.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_44.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mt7915_mcu_set_fixed_rate_ctrl")
		and target_44.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("mt7915_dev *")
		and target_44.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("ieee80211_vif *")
		and target_44.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsta_486
		and target_44.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("sta_phy")
		and target_44.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("u32")
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_44 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_44))
}

predicate func_45(Function func) {
	exists(IfStmt target_45 |
		target_45.getCondition().(VariableAccess).getType().hasName("int")
		and target_45.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-14"
		and target_45.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_45 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_45))
}

predicate func_47(Variable vmsta_487) {
	exists(PointerFieldAccess target_47 |
		target_47.getTarget().getName()="dev"
		and target_47.getQualifier().(PointerFieldAccess).getTarget().getName()="phy"
		and target_47.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vif"
		and target_47.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsta_487
		and target_47.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr() instanceof FunctionCall)
}

predicate func_49(Variable vsta_486) {
	exists(PointerFieldAccess target_49 |
		target_49.getTarget().getName()="drv_priv"
		and target_49.getQualifier().(VariableAccess).getTarget()=vsta_486)
}

from Function func, Parameter vdata_484, Parameter vrate_484, Variable vsta_486, Variable vmsta_487
where
func_0(vdata_484)
and func_1(vrate_484, vsta_486)
and not func_2(func)
and not func_3(func)
and not func_4(func)
and not func_5(func)
and not func_6(func)
and not func_7(func)
and not func_8(func)
and not func_9(func)
and not func_10(func)
and not func_11(func)
and not func_12(func)
and not func_13(func)
and not func_32(func)
and not func_33(vsta_486, func)
and not func_36(func)
and not func_37(func)
and not func_38(vmsta_487, func)
and not func_44(vsta_486, func)
and not func_45(func)
and func_47(vmsta_487)
and vdata_484.getType().hasName("void *")
and vrate_484.getType().hasName("u64")
and vsta_486.getType().hasName("ieee80211_sta *")
and func_49(vsta_486)
and vmsta_487.getType().hasName("mt7915_sta *")
and vdata_484.getParentScope+() = func
and vrate_484.getParentScope+() = func
and vsta_486.getParentScope+() = func
and vmsta_487.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
