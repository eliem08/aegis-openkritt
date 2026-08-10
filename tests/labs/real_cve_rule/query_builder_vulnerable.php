<?php
foreach ($this->QBWhere as $key => $where) {
    foreach ($this->binds as $field => $bind) {
        $this->QBWhere[$key]['condition'] = str_replace(':' . $field . ':', $bind[0], $where['condition']);
    }
}
