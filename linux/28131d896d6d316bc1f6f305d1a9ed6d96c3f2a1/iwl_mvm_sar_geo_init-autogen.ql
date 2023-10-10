/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_sar_geo_init
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-sar-geo-init
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_sar_geo_init CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_2)
}

predicate func_3(Function func) {
	exists(LogicalOrExpr target_3 |
		target_3.getValue()="0"
		and target_3.getAnOperand().(LogicalOrExpr).getValue()="0"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getValue()="0"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="0"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="ops"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="0"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="ops"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="ops"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="ops"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

predicate func_7(Variable vcmd_ver_813) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u32")
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="8"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmd_ver_813
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="5")
}

predicate func_12(Variable vcmd_ver_813) {
	exists(IfStmt target_12 |
		target_12.getCondition() instanceof EqualityOperation
		and target_12.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_12.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_12.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u32")
		and target_12.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
		and target_12.getElse().(IfStmt).getCondition() instanceof FunctionCall
		and target_12.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_12.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_12.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u32")
		and target_12.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
		and target_12.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_12.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_12.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u32")
		and target_12.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
		and target_12.getParent().(IfStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmd_ver_813
		and target_12.getParent().(IfStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="5")
}

predicate func_16(Function func) {
	exists(LogicalOrExpr target_16 |
		target_16.getValue()="0"
		and target_16.getAnOperand().(LogicalOrExpr).getValue()="0"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getValue()="0"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="4"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="table"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="4"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="table"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_16.getAnOperand().(EqualityOperation).getValue()="0"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="4"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="table"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="4"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="table"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_16.getEnclosingFunction() = func)
}

predicate func_18(Parameter vmvm_807, Variable vcmd_809, Variable vcmd_ver_813, Function func) {
	exists(IfStmt target_18 |
		target_18.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmd_ver_813
		and target_18.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="5"
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="table_revision"
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v5"
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="geo_rev"
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_807
		and target_18.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmd_ver_813
		and target_18.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_18.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="table_revision"
		and target_18.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v4"
		and target_18.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_18.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="geo_rev"
		and target_18.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_18.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_807
		and target_18.getElse().(IfStmt).getElse() instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_18 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_18))
}

predicate func_19(Function func) {
	exists(LogicalOrExpr target_19 |
		target_19.getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="ops"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="ops"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="ops"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="ops"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_19.getEnclosingFunction() = func)
}

predicate func_24(Parameter vmvm_807, Variable vcmd_809, Variable vlen_810) {
	exists(ExprStmt target_24 |
		target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_810
		and target_24.getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getValue()="32"
		and target_24.getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="v2"
		and target_24.getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("fw_has_api")
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ucode_capa"
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="fw"
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_807)
}

predicate func_25(Parameter vmvm_807, Variable vcmd_809, Variable vn_bands_811) {
	exists(ExprStmt target_25 |
		target_25.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_bands_811
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getValue()="2"
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getValue()="2"
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="table"
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v2"
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="table"
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v2"
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_25.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="0"
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("fw_has_api")
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ucode_capa"
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="fw"
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_807)
}

predicate func_26(Parameter vmvm_807, Variable vcmd_809, Variable vlen_810) {
	exists(ExprStmt target_26 |
		target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_810
		and target_26.getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getValue()="28"
		and target_26.getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="v1"
		and target_26.getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("fw_has_api")
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ucode_capa"
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="fw"
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_807)
}

predicate func_27(Parameter vmvm_807, Variable vcmd_809, Variable vn_bands_811) {
	exists(ExprStmt target_27 |
		target_27.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_bands_811
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getValue()="2"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getValue()="2"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="table"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v1"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="table"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v1"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="0"
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("fw_has_api")
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ucode_capa"
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="fw"
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_807)
}

predicate func_28(Function func) {
	exists(LogicalOrExpr target_28 |
		target_28.getValue()="0"
		and target_28.getAnOperand().(EqualityOperation).getValue()="0"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="4"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="table"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="4"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="table"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_28.getAnOperand().(EqualityOperation).getValue()="0"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="4"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="table"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="4"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="table"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_28.getEnclosingFunction() = func)
}

predicate func_29(Parameter vmvm_807, Variable vcmd_809, Variable vcmd_ver_813, Function func) {
	exists(IfStmt target_29 |
		target_29.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmd_ver_813
		and target_29.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_29.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="table_revision"
		and target_29.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v3"
		and target_29.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_29.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="geo_rev"
		and target_29.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_29.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_807
		and target_29.getElse().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("fw_has_api")
		and target_29.getElse().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ucode_capa"
		and target_29.getElse().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="fw"
		and target_29.getElse().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_29.getElse().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_807
		and target_29.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="table_revision"
		and target_29.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v2"
		and target_29.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_809
		and target_29.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="geo_rev"
		and target_29.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_29.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_807
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_29)
}

predicate func_30(Parameter vmvm_807) {
	exists(PointerFieldAccess target_30 |
		target_30.getTarget().getName()="fwrt"
		and target_30.getQualifier().(VariableAccess).getTarget()=vmvm_807)
}

from Function func, Parameter vmvm_807, Variable vcmd_809, Variable vlen_810, Variable vn_bands_811, Variable vcmd_ver_813
where
not func_2(func)
and not func_3(func)
and not func_7(vcmd_ver_813)
and not func_12(vcmd_ver_813)
and not func_16(func)
and not func_18(vmvm_807, vcmd_809, vcmd_ver_813, func)
and func_19(func)
and func_24(vmvm_807, vcmd_809, vlen_810)
and func_25(vmvm_807, vcmd_809, vn_bands_811)
and func_26(vmvm_807, vcmd_809, vlen_810)
and func_27(vmvm_807, vcmd_809, vn_bands_811)
and func_28(func)
and func_29(vmvm_807, vcmd_809, vcmd_ver_813, func)
and vmvm_807.getType().hasName("iwl_mvm *")
and func_30(vmvm_807)
and vcmd_809.getType().hasName("iwl_geo_tx_power_profiles_cmd")
and vlen_810.getType().hasName("u16")
and vn_bands_811.getType().hasName("u32")
and vcmd_ver_813.getType().hasName("u8")
and vmvm_807.getParentScope+() = func
and vcmd_809.getParentScope+() = func
and vlen_810.getParentScope+() = func
and vn_bands_811.getParentScope+() = func
and vcmd_ver_813.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
